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

import io.mosip.kernel.core.logger.spi.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import io.mosip.commons.khazana.spi.ObjectStoreAdapter;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.constant.IdRepoErrorConstants;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.core.fsadapter.exception.FSAdapterException;

/**
 * Optimized helper for object store access.
 * - Streams reads/writes internally and closes streams.
 * - Avoids redundant exists() calls before get/delete.
 * - Preserves all public method signatures.
 */
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

	private ObjectStoreAdapter objectStore;

	private final Logger mosipLogger = IdRepoLogger.getLogger(ObjectStoreHelper.class);

	@Autowired
	public void setObjectStore(ApplicationContext context) {
		this.objectStore = context.getBean(objectStoreAdapterName, ObjectStoreAdapter.class);
	}

	@Autowired
	private IdRepoSecurityManager securityManager;

	/* ------------------------ Public checks ------------------------ */

	public boolean demographicObjectExists(String uinHash, String fileRefId) {
		return exists(uinHash, false, fileRefId);
	}

	public boolean biometricObjectExists(String uinHash, String fileRefId) {
		return exists(uinHash, true, fileRefId);
	}

	/* ------------------------ Puts ------------------------ */

	public void putDemographicObject(String uinHash, String fileRefId, byte[] data) throws IdRepoAppException {
		putObject(uinHash, false, fileRefId, data, demoDataRefId);
	}

	public void putBiometricObject(String uinHash, String fileRefId, byte[] data) throws IdRepoAppException {
		putObject(uinHash, true, fileRefId, data, bioDataRefId);
	}

	/* ------------------------ Gets ------------------------ */

	public byte[] getDemographicObject(String uinHash, String fileRefId) throws IdRepoAppException {
		// Avoid pre-exists() network call; just try to read and handle not found.
		return getObject(uinHash, false, fileRefId, demoDataRefId);
	}

	public byte[] getBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		// Avoid pre-exists() network call; just try to read and handle not found.
		return getObject(uinHash, true, fileRefId, bioDataRefId);
	}

	/* ------------------------ Delete ------------------------ */

	public void deleteBiometricObject(String uinHash, String fileRefId) {
		// One network call; let the adapter/S3 ignore not-found gracefully.
		String objectName = buildObjectName(uinHash, true, fileRefId);
		try {
			objectStore.deleteObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
		} catch (Throwable t) {
			// Swallow not-found, log others
			mosipLogger.warn("deleteBiometricObject: delete failed for key {}", objectName, t);
		}
	}

	/* ------------------------ Private core ------------------------ */

	private boolean exists(String uinHash, boolean isBio, String fileRefId) {
		String objectName = buildObjectName(uinHash, isBio, fileRefId);
		try {
			return objectStore.exists(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
		} catch (Throwable t) {
			mosipLogger.warn("exists check failed for key {}", objectName, t);
			return false;
		}
	}

	private void putObject(String uinHash, boolean isBio, String fileRefId, byte[] data, String refId)
			throws IdRepoAppException {

		String objectName = buildObjectName(uinHash, isBio, fileRefId);
		try {
			// NOTE: API accepts byte[]; we must encrypt to byte[] here.
			// Use try-with-resources to ensure stream closure on the adapter side.
			byte[] encrypted = securityManager.encrypt(data, refId);
			try (InputStream in = new ByteArrayInputStream(encrypted)) {
				objectStore.putObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName, in);
			}
		} catch (FSAdapterException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (Throwable e) {
			mosipLogger.error("putObject: unexpected error for key {}", objectName, e);
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId) throws IdRepoAppException {
		String objectName = buildObjectName(uinHash, isBio, fileRefId);
		try (InputStream objectStream =
					 objectStore.getObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName)) {

			if (objectStream == null) {
				throw new IdRepoAppException(FILE_NOT_FOUND);
			}

			// Stream into a single growable buffer (avoids IOUtils extra copy).
			byte[] encrypted = readAll(objectStream);

			// Decrypt after read (API expects byte[])
			return securityManager.decrypt(encrypted, refId);

		} catch (FSAdapterException e) {
			throw new IdRepoAppException(IdRepoErrorConstants.FILE_STORAGE_ACCESS_ERROR, e);
		} catch (IdRepoAppException e) {
			// rethrow FILE_NOT_FOUND as-is
			throw e;
		} catch (Throwable e) {
			mosipLogger.error("getObject: unexpected error for key {}", objectName, e);
			throw new IdRepoAppException(IdRepoErrorConstants.FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	/* ------------------------ Helpers ------------------------ */

	private String buildObjectName(String uinHash, boolean isBio, String fileRefId) {
		return uinHash + SLASH + (isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;
	}

	/**
	 * Efficiently reads an InputStream into a byte[] with a reusable 64 KiB buffer.
	 */
	private static byte[] readAll(InputStream in) throws Exception {
		// 64 KiB buffer gives good throughput without huge heap spikes.
		final int BUF = 64 * 1024;
		byte[] buffer = new byte[BUF];
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
			int read;
			while ((read = in.read(buffer, 0, BUF)) != -1) {
				bos.write(buffer, 0, read);
			}
			return bos.toByteArray();
		}
	}
}
