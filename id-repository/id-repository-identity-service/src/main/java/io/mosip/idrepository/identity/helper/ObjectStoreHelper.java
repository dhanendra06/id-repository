package io.mosip.idrepository.identity.helper;

import static io.mosip.idrepository.core.constant.IdRepoConstants.*;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.commons.io.IOUtils;
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

	@Value("${mosip.idrepo.objectstore.max-object-size-bytes:10485760}")
	private long maxObjectSizeBytes = 10 * 1024 * 1024L; // 10 MB; also configurable via property

	private ObjectStoreAdapter objectStore;

	private Logger mosipLogger = IdRepoLogger.getLogger(ObjectStoreHelper.class);

	@Autowired
	public void setObjectStore(ApplicationContext context) {
		this.objectStore = context.getBean(objectStoreAdapterName, ObjectStoreAdapter.class);
	}

	@Autowired
	private IdRepoSecurityManager securityManager;

	public boolean demographicObjectExists(String uinHash, String fileRefId)  {
		return exists(uinHash, false, fileRefId);
	}

	public boolean biometricObjectExists(String uinHash, String fileRefId)  {
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
		boolean exists;
		try {
			exists = this.biometricObjectExists(uinHash, fileRefId);
		} catch (ObjectStoreAdapterException | IllegalStateException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to check object existence: " + e.getMessage(), e);
		}
		if (!exists) {
			throw new IdRepoAppException(FILE_NOT_FOUND);
		}
		return getObject(uinHash, true, fileRefId, bioDataRefId);
	}

	public void deleteBiometricObject(String uinHash, String fileRefId)  {
		// Object store deletes are idempotent; skip the existence pre-check HEAD request (O3).
		String objectName = uinHash + SLASH + BIOMETRICS + SLASH + fileRefId;
		objectStore.deleteObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
	}

	private boolean exists(String uinHash, boolean isBio, String fileRefId)  {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
			return objectStore.exists(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
	}

	private void putObject(String uinHash, boolean isBio, String fileRefId, byte[] data, String refId)
			throws IdRepoAppException {
		if (data == null || data.length == 0) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Input data is null or empty");
		}

		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;

		try (InputStream encryptData = new ByteArrayInputStream(securityManager.encrypt(data, refId))) {
			objectStore.putObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName, encryptData);
			mosipLogger.debug("Uploaded object: {} ({} bytes)", objectName, data.length);
		} catch (IOException | ObjectStoreAdapterException | IllegalStateException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to store object: " + e.getMessage(), e);
		}
	}


	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId)
			throws IdRepoAppException {
		String objectName = uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
		InputStream rawStream;
		try {
			rawStream = objectStore.getObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
		} catch (ObjectStoreAdapterException | IllegalStateException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to retrieve object: " + e.getMessage(), e);
		}
		if (rawStream == null) {
			throw new IdRepoAppException(FILE_NOT_FOUND);
		}
		// Read the S3 stream fully so the HTTP connection is cleanly returned to the pool.
		// BoundedInputStream must NOT be used here — stopping mid-stream causes S3ObjectInputStream
		// to abort the underlying HTTP connection instead of returning it, degrading the pool.
		try (InputStream s3Stream = rawStream) {
			byte[] encryptedData = IOUtils.toByteArray(s3Stream);
			if (encryptedData.length > maxObjectSizeBytes) {
				throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
						"Object size exceeds allowed limit (" + maxObjectSizeBytes + " bytes): " + objectName);
			}
			byte[] decryptedData = securityManager.decrypt(encryptedData, refId);
			encryptedData = null;
			return decryptedData;
		} catch (IOException | ObjectStoreAdapterException | IllegalStateException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to retrieve object: " + e.getMessage(), e);
		}
	}
}
