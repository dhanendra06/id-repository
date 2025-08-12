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
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.Callable;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

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

	@Value("${object.store.connection.max.retry:3}")
	private int maxRetry;

	@Value("${object.store.chunk.size:1548576}") // 1MB chunks for streaming
	private int chunkSize;

	private ObjectStoreAdapter objectStore;

	private Logger mosipLogger = IdRepoLogger.getLogger(ObjectStoreHelper.class);

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
		if (!this.demographicObjectExists(uinHash, fileRefId)) {
			throw new IdRepoAppException(FILE_NOT_FOUND);
		}
		return getObject(uinHash, false, fileRefId, demoDataRefId);
	}

	public byte[] getBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (!this.biometricObjectExists(uinHash, fileRefId)) {
			throw new IdRepoAppException(FILE_NOT_FOUND);
		}
		return getObject(uinHash, true, fileRefId, bioDataRefId);
	}

	public void deleteBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (this.biometricObjectExists(uinHash, fileRefId)) {
			String objectName = uinHash + SLASH + BIOMETRICS + SLASH + fileRefId;
			retry(() -> objectStore.deleteObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName),
					"deleteObject");
		}
	}

	private boolean exists(String uinHash, boolean isBio, String fileRefId) throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		return retry(() -> objectStore.exists(objectStoreAccountName, objectStoreBucketName, null, null, objectName),
				"exists");
	}

	private void putObject(String uinHash, boolean isBio, String fileRefId, byte[] data, String refId)
			throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		try {
			long encryptStartTime = System.currentTimeMillis();
			ByteArrayOutputStream encryptedStream = new ByteArrayOutputStream();
			try (InputStream input = new ByteArrayInputStream(data)) {
				byte[] buffer = new byte[chunkSize];
				int bytesRead;
				while ((bytesRead = input.read(buffer)) != -1) {
					byte[] chunk = bytesRead == chunkSize ? buffer : Arrays.copyOf(buffer, bytesRead);
					encryptedStream.write(securityManager.encrypt(chunk, refId));
				}
			}
			mosipLogger.debug("Encryption time for {}: {} ms", objectName, System.currentTimeMillis() - encryptStartTime);
			try (InputStream encryptData = new ByteArrayInputStream(encryptedStream.toByteArray())) {
				retry(() -> objectStore.putObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName, encryptData),
						"putObject");
			}
		} catch (IOException e) {
			mosipLogger.error("IOException during putObject for: " + objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (Exception e) {
			mosipLogger.error("Exception during putObject for: " + objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId) throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		try {
			long startTime = System.currentTimeMillis();
			try (InputStream s3Stream = retry(() -> objectStore.getObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName),
					"getObject")) {
				if (s3Stream == null) {
					throw new IdRepoAppException(FILE_NOT_FOUND);
				}
				mosipLogger.debug("S3 getObject time for {}: {} ms", objectName, System.currentTimeMillis() - startTime);
				long decryptStartTime = System.currentTimeMillis();
				ByteArrayOutputStream decryptedStream = new ByteArrayOutputStream();
				byte[] buffer = new byte[chunkSize];
				int bytesRead;
				while ((bytesRead = s3Stream.read(buffer)) != -1) {
					byte[] chunk = bytesRead == chunkSize ? buffer : Arrays.copyOf(buffer, bytesRead);
					decryptedStream.write(securityManager.decrypt(chunk, refId));
				}
				mosipLogger.debug("Decryption time for {}: {} ms", objectName, System.currentTimeMillis() - decryptStartTime);
				return decryptedStream.toByteArray();
			}
		} catch (IOException e) {
			mosipLogger.error("IOException during getObject for: " + objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (Exception e) {
			mosipLogger.error("Exception during getObject for: " + objectName, ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	private <T> T retry(Callable<T> operation, String operationName) throws IdRepoAppException {
		for (int attempt = 1; attempt <= maxRetry; attempt++) {
			try {
				return operation.call();
			} catch (Exception e) {
				mosipLogger.warn("Error during {} attempt {} for: {}", operationName, attempt, objectStoreBucketName, ExceptionUtils.getStackTrace(e));
				if (attempt == maxRetry) {
					throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "Operation failed after " + maxRetry + " attempts", e);
				}
				try {
					Thread.sleep(1000L * attempt); // Exponential backoff
				} catch (InterruptedException ie) {
					Thread.currentThread().interrupt();
					throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(), "Interrupted during retry", ie);
				}
			}
		}
		return null;
	}
}