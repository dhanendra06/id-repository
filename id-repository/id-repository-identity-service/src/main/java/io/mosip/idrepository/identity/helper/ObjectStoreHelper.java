package io.mosip.idrepository.identity.helper;

import static io.mosip.idrepository.core.constant.IdRepoConstants.*;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.*;

import java.io.*;
import java.util.Arrays;
import java.util.concurrent.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;
import io.mosip.commons.khazana.exception.ObjectStoreAdapterException;
import io.mosip.commons.khazana.spi.ObjectStoreAdapter;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.exception.ExceptionUtils;

@Component
public class ObjectStoreHelper {
	@Value("${" + BIO_DATA_REFID + "}")
	private String bioDataRefId;
	@Value("${" + DEMO_DATA_REFID + "}")
	private String demoDataRefId;
	@Value("${" + OBJECT_STORE_ACCOUNT_NAME + "}")
	private String objectStoreAccountName;
	@Value("${" + OBJECT_STORE_BUCKET_NAME + "}")
	private String objectStoreBucketName;
	@Value("${" + OBJECT_STORE_ADAPTER_NAME + "}")
	private String objectStoreAdapterName;
	@Value("${object.store.connection.max.retry:10}")
	private int maxRetry;
	@Value("${object.store.chunk.size:1048576}")
	private int chunkSize; // Default: 1MB
	@Value("${object.store.operation.timeout:10000}")
	private int operationTimeout;

	private static final String SLASH = "/";
	private static final String BIOMETRICS = "Biometrics";
	private static final String DEMOGRAPHICS = "Demographics";

	private ObjectStoreAdapter objectStore;
	private final Logger mosipLogger = IdRepoLogger.getLogger(ObjectStoreHelper.class);
	private final ExecutorService cryptoPool = Executors.newFixedThreadPool(
			Math.max(2, Runtime.getRuntime().availableProcessors())
	);

	@Autowired
	public void setObjectStore(ApplicationContext context) {
		this.objectStore = context.getBean(objectStoreAdapterName, ObjectStoreAdapter.class);
	}

	@Autowired
	private IdRepoSecurityManager securityManager;

	public boolean demographicObjectExists(String uinHash, String fileRefId) throws IdRepoAppException {
		return exists(uinHash, false, fileRefId);
	}

	public boolean biometricObjectExists(String uinHash, String fileRefId) throws IdRepoAppException {
		return exists(uinHash, true, fileRefId);
	}

	public void putDemographicObject(String uinHash, String fileRefId, byte[] data) throws IdRepoAppException {
		putObject(uinHash, false, fileRefId, data, demoDataRefId);
	}

	public void putBiometricObject(String uinHash, String fileRefId, byte[] data) throws IdRepoAppException {
		putObject(uinHash, true, fileRefId, data, bioDataRefId);
	}

	public byte[] getDemographicObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (!demographicObjectExists(uinHash, fileRefId)) {
			throw new IdRepoAppException(FILE_NOT_FOUND);
		}
		return getObject(uinHash, false, fileRefId, demoDataRefId);
	}

	public byte[] getBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (!biometricObjectExists(uinHash, fileRefId)) {
			throw new IdRepoAppException(FILE_NOT_FOUND);
		}
		return getObject(uinHash, true, fileRefId, bioDataRefId);
	}

	public void deleteBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (biometricObjectExists(uinHash, fileRefId)) {
			String objectName = uinHash + SLASH + BIOMETRICS + SLASH + fileRefId;
			mosipLogger.info("Attempting to delete biometric object: " + objectName);
			retry(() -> objectStore.deleteObject(
					objectStoreAccountName, objectStoreBucketName, null, null, objectName
			));
			mosipLogger.info("Successfully deleted biometric object: " + objectName);
		}
	}

	private boolean exists(String uinHash, boolean isBio, String fileRefId) throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		try {
			return retry(() -> objectStore.exists(objectStoreAccountName, objectStoreBucketName, null, null, objectName));
		} catch (ObjectStoreAdapterException e) {
			mosipLogger.error("ObjectStoreAdapterException during exists check for: " + objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to check object existence: " + e.getErrorCode(), e);
		}
	}

	private void putObject(String uinHash, boolean isBio, String fileRefId, byte[] data, String refId) throws IdRepoAppException {
		if (data == null || data.length == 0) {
			mosipLogger.error("Invalid input data for putObject: uinHash={}, fileRefId={}", uinHash, fileRefId);
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "Input data is null or empty");
		}
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		try {
			int totalChunks = (data.length + chunkSize - 1) / chunkSize;
			Future<byte[]>[] futures = new Future[totalChunks];
			for (int i = 0; i < totalChunks; i++) {
				int start = i * chunkSize;
				int end = Math.min(data.length, (i + 1) * chunkSize);
				byte[] chunk = Arrays.copyOfRange(data, start, end);
				futures[i] = cryptoPool.submit(() -> securityManager.encrypt(chunk, refId));
			}
			ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream(data.length);
			for (int i = 0; i < totalChunks; i++) {
				encryptedStream.write(futures[i].get());
			}
			try (InputStream encryptData = new ByteArrayInputStream(encryptedStream.toByteArray())) {
				retry(() -> objectStore.putObject(
						objectStoreAccountName, objectStoreBucketName, null, null, objectName, encryptData));
			}
		} catch (IOException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (ObjectStoreAdapterException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"S3 error: " + e.getErrorCode(), e);
		} catch (Exception e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId) throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		try (InputStream s3Stream = retry(() -> objectStore.getObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName))) {
			if (s3Stream == null) {
				throw new IdRepoAppException(FILE_NOT_FOUND);
			}
			byte[][] encryptedChunks = readAllChunks(s3Stream, chunkSize);
			int chunkNum = encryptedChunks.length;
			Future<byte[]>[] futures = new Future[chunkNum];
			for (int i = 0; i < chunkNum; i++) {
				final int idx = i;
				futures[i] = cryptoPool.submit(() -> securityManager.decrypt(encryptedChunks[idx], refId));
			}
			ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
			for (Future<byte[]> future : futures) {
				decryptedStream.write(future.get());
			}
			return decryptedStream.toByteArray();
		} catch (IOException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (ObjectStoreAdapterException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "S3 error: " + e.getErrorCode(), e);
		} catch (Exception e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	// Reads stream as N chunks, returns byte[][]
	private byte[][] readAllChunks(InputStream is, int chunkSize) throws IOException {
		byte[][] temp = new byte[16][];
		int count = 0;
		byte[] buffer = new byte[chunkSize];
		int read;
		while ((read = is.read(buffer)) != -1) {
			if (count == temp.length) temp = Arrays.copyOf(temp, temp.length * 2);
			temp[count++] = Arrays.copyOf(buffer, read);
		}
		return Arrays.copyOf(temp, count);
	}

	private <T> T retry(Callable<T> operation) throws IdRepoAppException {
		for (int attempt = 1; attempt <= maxRetry; attempt++) {
			try {
				return operation.call();
			} catch (Exception e) {
				if (attempt == maxRetry) {
					throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
							"Operation failed after " + maxRetry + " attempts", e);
				}
				try { Thread.sleep(200L * attempt); } catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "Retry interrupted", ie);
				}
			}
		}
		return null;
	}
}