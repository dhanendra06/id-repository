package io.mosip.idrepository.identity.helper;

import static io.mosip.idrepository.core.constant.IdRepoConstants.*;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.*;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.Semaphore;

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

	/**
	 * CONFIGURABLE crypto concurrency gate.
	 * Default: 8 (good for 2-4 vCPU)
	 */
	@Value("${idrepo.crypto.max-concurrency:8}")
	private int cryptoMaxConcurrency;

	private Semaphore cryptoSemaphore;

	private ObjectStoreAdapter objectStore;

	private Logger mosipLogger = IdRepoLogger.getLogger(ObjectStoreHelper.class);

	@Autowired
	public void setObjectStore(ApplicationContext context) {
		this.objectStore = context.getBean(objectStoreAdapterName, ObjectStoreAdapter.class);
	}

	@Autowired
	private IdRepoSecurityManager securityManager;

	@Autowired
	public void initSemaphore() {
		this.cryptoSemaphore = new Semaphore(cryptoMaxConcurrency);
	}

	/* ======================= EXISTS ======================= */

	public boolean demographicObjectExists(String uinHash, String fileRefId) {
		return exists(uinHash, false, fileRefId);
	}

	public boolean biometricObjectExists(String uinHash, String fileRefId) {
		return exists(uinHash, true, fileRefId);
	}

	/* ========================= PUT ======================== */

	public void putDemographicObject(String uinHash, String fileRefId, byte[] data) throws IdRepoAppException {
		putObject(uinHash, false, fileRefId, data, demoDataRefId);
	}

	public void putBiometricObject(String uinHash, String fileRefId, byte[] data) throws IdRepoAppException {
		putObject(uinHash, true, fileRefId, data, bioDataRefId);
	}

	private void putObject(String uinHash, boolean isBio, String fileRefId, byte[] data, String refId)
			throws IdRepoAppException {

		if (data == null || data.length == 0) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Input data is null or empty");
		}

		String objectName = uinHash + SLASH +
				(isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;

		boolean acquired = false;

		try {
			cryptoSemaphore.acquire();
			acquired = true;

			byte[] encrypted = securityManager.encrypt(data, refId);

			try (InputStream stream = new ByteArrayInputStream(encrypted)) {
				objectStore.putObject(
						objectStoreAccountName, objectStoreBucketName,
						null, null, objectName,
						stream
				);
			}

			mosipLogger.debug("Uploaded object: {} ({} bytes)", objectName, data.length);

		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Interrupted while encrypting", e);

		} catch (IOException | ObjectStoreAdapterException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to store object: " + e.getMessage(), e);

		} finally {
			if (acquired) cryptoSemaphore.release();
		}
	}

	/* ======================== GET ========================= */

	public byte[] getDemographicObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (!demographicObjectExists(uinHash, fileRefId))
			throw new IdRepoAppException(FILE_NOT_FOUND);
		return getObject(uinHash, false, fileRefId, demoDataRefId);
	}

	public byte[] getBiometricObject(String uinHash, String fileRefId) throws IdRepoAppException {
		if (!biometricObjectExists(uinHash, fileRefId))
			throw new IdRepoAppException(FILE_NOT_FOUND);
		return getObject(uinHash, true, fileRefId, bioDataRefId);
	}

	private byte[] getObject(String uinHash, boolean isBio, String fileRefId, String refId)
			throws IdRepoAppException {

		String objectName = uinHash + SLASH +
				(isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;

		InputStream rawStream =
				objectStore.getObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName);

		if (rawStream == null)
			throw new IdRepoAppException(FILE_NOT_FOUND);

		boolean acquired = false;

		try (InputStream s3Stream = new BufferedInputStream(rawStream)) {

			cryptoSemaphore.acquire();
			acquired = true;

			byte[] encryptedData = IOUtils.toByteArray(s3Stream);
			return securityManager.decrypt(encryptedData, refId);

		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Interrupted during decrypt", e);

		} catch (IOException | ObjectStoreAdapterException e) {
			throw new IdRepoAppException(FILE_STORAGE_ACCESS_ERROR.getErrorCode(),
					"Failed to retrieve object: " + e.getMessage(), e);

		} finally {
			if (acquired) cryptoSemaphore.release();
		}
	}

	/* ======================== DELETE ======================= */

	public void deleteBiometricObject(String uinHash, String fileRefId) {
		if (biometricObjectExists(uinHash, fileRefId)) {
			String objectName = uinHash + SLASH + BIOMETRICS + SLASH + fileRefId;
			objectStore.deleteObject(objectStoreAccountName, objectStoreBucketName, null, null, objectName);
		}
	}

	/* ======================== INTERNAL ======================= */

	private boolean exists(String uinHash, boolean isBio, String fileRefId) {
		String name = uinHash + SLASH +
				(isBio ? BIOMETRICS : DEMOGRAPHICS) + SLASH + fileRefId;

		return objectStore.exists(
				objectStoreAccountName, objectStoreBucketName, null, null, name
		);
	}
}
