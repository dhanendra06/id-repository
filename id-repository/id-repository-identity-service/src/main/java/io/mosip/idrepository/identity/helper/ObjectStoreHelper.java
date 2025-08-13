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
 * Optimized helper for object store access (1–4 MB objects).
 * - Drop-in compatible: public method signatures unchanged.
 * - Eliminates redundant exists() before get/delete.
 * - Streams with a reusable buffer to reduce allocations/GC.
 * - Ensures streams/connections are closed promptly.
 * - Adds light timing logs for performance visibility.
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

	// Reuse a single 64 KiB buffer per thread to cut allocations/GC pressure
	private static final int READ_BUF_SIZE = 64 * 1024;
	private static final ThreadLocal<byte[]> TL_BUFFER = ThreadLocal.withInitial(() -> new byte[READ_BUF_SIZE]);

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
		// Avoid pre-exists() trip; handle not-found from the read path
		return getObject(uinHash, false, fileRefId, demoDataRefId);
	}

	public byte[] getBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		// Avoid pre-exists() trip; handle not-found from the read path
		return getObject(uinHash, true, fileRefId, bioDataRefId);
	}

	/* ------------------------ Delete ------------------------ */

	public void deleteBiometricObject(String uinHash, String fileRefId) {
		final String objectName = buildObjectName(uinHash, true, fileRefId);
		try {
			objectStore.deleteObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
		} catch (Throwable t) {
			// Ignore not-found; log others and continue
			mosipLogger.warn("deleteBiometricObject: delete failed for key {}", objectName, t);
		}
	}

	/* ------------------------ Private core ------------------------ */

	private boolean exists(String uinHash, boolean isBio, String fileRefId) {
		final String objectName = buildObjectName(uinHash, isBio, fileRefId);
		try {
			return objectStore.exists(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
		} catch (Throwable t) {
			mosipLogger.warn("exists check failed for key {}", objectName, t);
			return false;
		}
	}

	private void putObject(String uinHash, boolean isBio, String fileRefId, byte[] data, String refId)
			throws IdRepoAppException {

		final String objectName = buildObjectName(uinHash, isBio, fileRefId);
		final long t0 = System.currentTimeMillis();
		try {
			// Encrypt in-memory (API requires byte[]) then stream it out
			final byte[] encrypted = securityManager.encrypt(data, refId);
			final long t1 = System.currentTimeMillis();

			try (InputStream in = new ByteArrayInputStream(encrypted)) {
				objectStore.putObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName, in);
			}
			final long t2 = System.currentTimeMillis();
			mosipLogger.info("putObject key={} encryptMs={} uploadMs={}",
						objectName, (t1 - t0), (t2 - t1));
		} catch (FSAdapterException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		} catch (Throwable e) {
			mosipLogger.error("putObject: unexpected error for key {}", objectName, e);
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR, e);
		}
	}

	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId) throws IdRepoAppException {
		final String objectName = buildObjectName(uinHash, isBio, fileRefId);
		final long t0 = System.currentTimeMillis();

		try (InputStream objectStream =
					 objectStore.getObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName)) {

			if (objectStream == null) {
				throw new IdRepoAppException(FILE_NOT_FOUND);
			}

			// Read encrypted payload with reusable buffer (no IOUtils extra copies)
			byte[] encrypted = readAll(objectStream);
			final long t1 = System.currentTimeMillis();

			byte[] plain = securityManager.decrypt(encrypted, refId);
			final long t2 = System.currentTimeMillis();
			mosipLogger.info("getObject key={} downloadMs={} decryptMs={}",
						objectName, (t1 - t0), (t2 - t1));
			return plain;

		} catch (FSAdapterException e) {
			throw new IdRepoAppException(IdRepoErrorConstants.FILE_STORAGE_ACCESS_ERROR, e);
		} catch (IdRepoAppException e) {
			throw e; // FILE_NOT_FOUND passthrough
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
	 * Efficiently reads an InputStream into a byte[] using a reusable 64 KiB buffer.
	 */
	private static byte[] readAll(InputStream in) throws Exception {
		byte[] buf = TL_BUFFER.get();
		try (ByteArrayOutputStream bos = new ByteArrayOutputStream(1024 * 1024)) { // pre-size ~1MB for 1–4MB typical
			int n;
			while ((n = in.read(buf, 0, buf.length)) != -1) {
				bos.write(buf, 0, n);
			}
			return bos.toByteArray();
		}
	}
}
