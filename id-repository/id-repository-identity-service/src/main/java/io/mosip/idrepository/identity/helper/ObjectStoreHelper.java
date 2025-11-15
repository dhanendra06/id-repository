package io.mosip.idrepository.identity.helper;

import static io.mosip.idrepository.core.constant.IdRepoConstants.BIO_DATA_REFID;
import static io.mosip.idrepository.core.constant.IdRepoConstants.DEMO_DATA_REFID;
import static io.mosip.idrepository.core.constant.IdRepoConstants.OBJECT_STORE_ACCOUNT_NAME;
import static io.mosip.idrepository.core.constant.IdRepoConstants.OBJECT_STORE_ADAPTER_NAME;
import static io.mosip.idrepository.core.constant.IdRepoConstants.OBJECT_STORE_BUCKET_NAME;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.FILE_NOT_FOUND;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.FILE_STORAGE_ACCESS_ERROR;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.concurrent.Callable;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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

	private static final String SLASH = "/";
	private static final String BIOMETRICS = "Biometrics";
	private static final String DEMOGRAPHICS = "Demographics";

	@Value("${" + OBJECT_STORE_ACCOUNT_NAME + "}")
	private String objectStoreAccountName;

	@Value("${" + OBJECT_STORE_BUCKET_NAME + "}")
	private String objectStoreBucketName;

	@Value("${" + OBJECT_STORE_ADAPTER_NAME + "}")
	private String objectStoreAdapterName;

	@Value("${object.store.connection.max.retry:10}")
	private int maxRetry;

	@Value("${object.store.chunk.size:1048576}")
	private int chunkSize;

	@Value("${object.store.operation.timeout:10000}")
	private int operationTimeout;

	// Reuse thread pool for chunk crypto
	private final ExecutorService cryptoPool = Executors.newFixedThreadPool(
			Math.max(2, Runtime.getRuntime().availableProcessors())
	);

	private ObjectStoreAdapter objectStore;
	private final Logger mosipLogger = IdRepoLogger.getLogger(ObjectStoreHelper.class);

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
			retry(() -> objectStore.deleteObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName));
			mosipLogger.info("Successfully deleted biometric object: " + objectName);
		}
	}

	private boolean exists(String uinHash, boolean isBio, String fileRefId) throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		mosipLogger.debug("Checking existence of object: {}", objectName);
		try {
			boolean exists = retry(() -> objectStore.exists(objectStoreAccountName, objectStoreBucketName, null, null, objectName));
			mosipLogger.debug("Object exists check for {}: {}", objectName, exists);
			return exists;
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
		mosipLogger.info("Putting object: {}", objectName);
		try {
			long encryptStart = System.currentTimeMillis();

			// Parallel chunk encryption
			int totalChunks = (data.length + chunkSize - 1) / chunkSize;
			Future<byte[]>[] futures = new Future[totalChunks];
			for (int i = 0; i < totalChunks; i++) {
				int chunkStart = i * chunkSize;
				int chunkEnd = Math.min(chunkStart + chunkSize, data.length);
				byte[] chunk = Arrays.copyOfRange(data, chunkStart, chunkEnd);
				final int idx = i;
				futures[i] = cryptoPool.submit(() -> securityManager.encrypt(chunk, refId));
			}
			ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream(data.length);
			for (int i = 0; i < totalChunks; i++) {
				encryptedStream.write(futures[i].get());
			}
			mosipLogger.debug("Encryption & parallelization time for {}: {} ms", objectName, (System.currentTimeMillis() - encryptStart));

			try (InputStream encryptData = new ByteArrayInputStream(encryptedStream.toByteArray())) {
				retry(() -> objectStore.putObject(
						objectStoreAccountName, objectStoreBucketName, null, null, objectName, encryptData));
			}
			mosipLogger.info("Successfully put object: {}", objectName);
		} catch (IOException e) {
			mosipLogger.error("IOException during putObject for: {}", objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (ObjectStoreAdapterException e) {
			mosipLogger.error("ObjectStoreAdapterException during putObject for: {}", objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"S3 error: " + e.getErrorCode(), e);
		} catch (Exception e) {
			mosipLogger.error("Unexpected exception during putObject for: {}", objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId) throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		mosipLogger.info("Getting object: {}", objectName);
		try (InputStream s3Stream = retry(() -> objectStore.getObject(
				objectStoreAccountName, objectStoreBucketName, null, null, objectName))) {
			if (s3Stream == null) {
				mosipLogger.error("Object not found: {}", objectName);
				throw new IdRepoAppException(FILE_NOT_FOUND);
			}
			long decryptStart = System.currentTimeMillis();
			ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();

			// Read all encrypted data and chunk for parallel decryption
			byte[][] encryptedChunks = readAllChunks(s3Stream, chunkSize);
			Future<byte[]>[] futures = new Future[encryptedChunks.length];
			for (int i = 0; i < encryptedChunks.length; i++) {
				final int idx = i;
				futures[i] = cryptoPool.submit(() -> securityManager.decrypt(encryptedChunks[idx], refId));
			}
			for (Future<byte[]> future : futures) {
				decryptedStream.write(future.get());
			}
			mosipLogger.debug("Decryption & parallelization time for {}: {} ms", objectName, (System.currentTimeMillis() - decryptStart));
			return decryptedStream.toByteArray();
		} catch (IOException e) {
			mosipLogger.error("IOException during getObject for: {}", objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (ObjectStoreAdapterException e) {
			mosipLogger.error("ObjectStoreAdapterException during getObject for: {}", objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "S3 error: " + e.getErrorCode(), e);
		} catch (Exception e) {
			mosipLogger.error("Unexpected exception during getObject for: {}", objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	// Utility to chunk an InputStream efficiently (without holding a huge buffer)
	private byte[][] readAllChunks(InputStream is, int chunkSize) throws IOException {
		ByteArrayOutputStream buffer = new ByteArrayOutputStream();
		byte[] chunk = new byte[chunkSize];
		int read;
		int count = 0;
		byte[][] temp = new byte[16][];
		while ((read = is.read(chunk)) != -1) {
			if (count == temp.length) {
				temp = Arrays.copyOf(temp, temp.length * 2); // Grow as needed
			}
			temp[count++] = Arrays.copyOf(chunk, read);
		}
		return Arrays.copyOf(temp, count);
	}

	// Retried execution with exponential backoff
	private <T> T retry(Callable<T> operation) throws IdRepoAppException {
		for (int attempt = 1; attempt <= maxRetry; attempt++) {
			try {
				return operation.call();
			} catch (Exception e) {
				mosipLogger.warn(
						"Error during object store operation attempt {} for bucket {}: {}",
						attempt, objectStoreBucketName, ExceptionUtils.getStackTrace(e));
				if (attempt == maxRetry) {
					throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
							"Operation failed after " + maxRetry + " attempts", e);
				}
				try {
					Thread.sleep(500L * attempt);
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "Interrupted during retry", ie);
				}
			}
		}
		return null;
	}
}