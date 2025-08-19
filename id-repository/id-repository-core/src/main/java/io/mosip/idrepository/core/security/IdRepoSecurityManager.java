package io.mosip.idrepository.core.security;

import static io.mosip.idrepository.core.constant.IdRepoConstants.CACHE_UPDATE_DEFAULT_INTERVAL;
import static io.mosip.idrepository.core.constant.IdRepoConstants.IDREPO_CACHE_UPDATE_INTERVAL;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.ENCRYPTION_DECRYPTION_FAILED;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.IntFunction;
import java.util.function.ToIntFunction;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.mosip.idrepository.core.builder.RestRequestBuilder;
import io.mosip.idrepository.core.constant.IdRepoErrorConstants;
import io.mosip.idrepository.core.constant.RestServicesConstants;
import io.mosip.idrepository.core.dto.RestRequestDTO;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.exception.IdRepoAppUncheckedException;
import io.mosip.idrepository.core.exception.RestServiceException;
import io.mosip.idrepository.core.helper.RestHelper;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.util.EnvUtil;
import io.mosip.idrepository.core.util.SaltUtil;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils;
import io.mosip.kernel.core.util.HMACUtils2;
import lombok.NoArgsConstructor;

/**
 * Provides security-related functionalities:
 * - Hashing (with/without salt)
 * - Encryption/decryption via kernel-cryptomanager
 * - Caching salt values
 * - User lookup
 */
@NoArgsConstructor
public class IdRepoSecurityManager {

	private static final String RESPONSE = "response";
	private static final String DATA = "data";
	private static final String REFERENCE_ID = "referenceId";
	private static final String PREPEND_THUMBPRINT = "prependThumbprint";
	private static final String APPLICATION_ID = "applicationId";
	private static final String TIME_STAMP = "timeStamp";
	private static final String STRING = "string";

	public static final String SALT = "SALT";
	public static final String MODULO = "MODULO";
	public static final String ID_HASH = "id_hash";

	private static final String ENCRYPT_DECRYPT_DATA = "encryptDecryptData";
	private static final String ID_REPO_SECURITY_MANAGER = "IdRepoSecurityManager";

	private final Logger logger = IdRepoLogger.getLogger(IdRepoSecurityManager.class);

	@Autowired
	private RestRequestBuilder restBuilder;

	private RestHelper restHelper;

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private ApplicationContext ctx;

	@Autowired
	private CacheManager cacheManager;

	public IdRepoSecurityManager(RestHelper restHelper) {
		this.restHelper = restHelper;
	}

	@PostConstruct
	public void init() {
		if (restHelper == null) {
			this.restHelper = ctx.getBean(RestHelper.class);
		}
	}

	/* ------------------- Hashing ------------------- */

	public String hash(final byte[] data) {
		try {
			return HMACUtils2.digestAsPlainText(data);
		} catch (NoSuchAlgorithmException e) {
			throw new IdRepoAppUncheckedException(IdRepoErrorConstants.UNKNOWN_ERROR, e);
		}
	}

	public String hashwithSalt(final byte[] data, final byte[] salt) {
		try {
			return HMACUtils2.digestAsPlainTextWithSalt(data, salt);
		} catch (NoSuchAlgorithmException e) {
			throw new IdRepoAppUncheckedException(IdRepoErrorConstants.UNKNOWN_ERROR, e);
		}
	}

	/* ------------------- User ------------------- */

	public static String getUser() {
		if (SecurityContextHolder.getContext() != null
				&& SecurityContextHolder.getContext().getAuthentication() != null
				&& SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UserDetails details) {
			return details.getUsername();
		}
		return "";
	}

	/* ------------------- Encryption / Decryption ------------------- */

	public byte[] encrypt(final byte[] dataToEncrypt, String refId) throws IdRepoAppException {
		ObjectNode request = mapper.createObjectNode();
		request.put(APPLICATION_ID, EnvUtil.getAppId());
		request.put(TIME_STAMP, DateUtils.formatDate(new Date(), EnvUtil.getDateTimePattern()));
		request.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToEncrypt));
		request.put(REFERENCE_ID, refId);
		request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());

		return callCryptoManager(RestServicesConstants.CRYPTO_MANAGER_ENCRYPT, request);
	}

	public byte[] encryptWithSalt(final byte[] data, final byte[] salt, String refId) throws IdRepoAppException {
		ObjectNode request = mapper.createObjectNode();
		request.put(APPLICATION_ID, EnvUtil.getAppId());
		request.put(TIME_STAMP, DateUtils.formatDate(new Date(), EnvUtil.getDateTimePattern()));
		request.put(DATA, CryptoUtil.encodeToURLSafeBase64(data));
		request.put("salt", CryptoUtil.encodeToURLSafeBase64(salt));
		request.put(REFERENCE_ID, refId);
		request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());

		return callCryptoManager(RestServicesConstants.CRYPTO_MANAGER_ENCRYPT, request);
	}

	public byte[] decrypt(final byte[] dataToDecrypt, String refId) throws IdRepoAppException {
		ObjectNode request = mapper.createObjectNode();
		request.put(APPLICATION_ID, EnvUtil.getAppId());
		request.put(REFERENCE_ID, refId);
		request.put(TIME_STAMP, DateUtils.formatDate(new Date(), EnvUtil.getDateTimePattern()));
		request.put(DATA, new String(dataToDecrypt)); // already Base64 string
		request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());

		return callCryptoManager(RestServicesConstants.CRYPTO_MANAGER_DECRYPT, request);
	}

	public byte[] decryptWithSalt(final byte[] data, final byte[] salt, String refId) throws IdRepoAppException {
		ObjectNode request = mapper.createObjectNode();
		request.put(APPLICATION_ID, EnvUtil.getAppId());
		request.put(REFERENCE_ID, refId);
		request.put(TIME_STAMP, DateUtils.formatDate(new Date(), EnvUtil.getDateTimePattern()));
		request.put(DATA, CryptoUtil.encodeToURLSafeBase64(data));
		request.put("salt", CryptoUtil.encodeToURLSafeBase64(salt));
		request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());

		return callCryptoManager(RestServicesConstants.CRYPTO_MANAGER_DECRYPT, request);
	}

	private byte[] callCryptoManager(RestServicesConstants service, ObjectNode requestNode) throws IdRepoAppException {
		try {
			RequestWrapper<ObjectNode> wrapper = new RequestWrapper<>();
			wrapper.setId(STRING);
			wrapper.setRequesttime(DateUtils.getUTCCurrentDateTime());
			wrapper.setVersion(EnvUtil.getAppVersion());
			wrapper.setRequest(requestNode);

			RestRequestDTO restRequest = restBuilder.buildRequest(service, wrapper, ObjectNode.class);
			ObjectNode response = restHelper.requestSync(restRequest);

			if (response.has(RESPONSE) && response.get(RESPONSE).has(DATA)) {
				String encoded = response.get(RESPONSE).get(DATA).asText();
				return CryptoUtil.decodeURLSafeBase64(encoded);
			}
			logger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, "No data block in response");
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED);

		} catch (RestServiceException e) {
			logger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
					ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, e);
		}
	}

	/* ------------------- Salt & Hash Attributes ------------------- */

	public String getIdHash(String uin, IntFunction<String> saltRetrieval) {
		return getIdHashAndAttributes(uin, saltRetrieval).get(ID_HASH);
	}

	public String getIdHashWithSaltModuloByPlainIdHash(String uin, IntFunction<String> saltRetrieval) {
		return getIdHashAndAttributesWithSaltModuloByPlainIdHash(uin, saltRetrieval).get(ID_HASH);
	}

	@Cacheable(cacheNames = "id_attributes")
	public Map<String, String> getIdHashAndAttributes(String id, IntFunction<String> saltRetrieval) {
		return getIdHashAndAttributes(id, saltRetrieval, this::getSaltKeyForId);
	}

	public Map<String, String> getIdHashAndAttributesWithSaltModuloByPlainIdHash(
			String id, IntFunction<String> saltRetrieval) {
		return getIdHashAndAttributes(id, saltRetrieval, this::getSaltKeyForHashOfId);
	}

	private Map<String, String> getIdHashAndAttributes(
			String id, IntFunction<String> saltRetrieval, ToIntFunction<String> saltIdFunction) {
		int saltId = saltIdFunction.applyAsInt(id);
		String hashSalt = saltRetrieval.apply(saltId);
		String hash = hashwithSalt(id.getBytes(), hashSalt.getBytes());

		Map<String, String> attributes = new HashMap<>();
		attributes.put(ID_HASH, hash);
		attributes.put(MODULO, String.valueOf(saltId));
		attributes.put(SALT, hashSalt);
		return attributes;
	}

	public int getSaltKeyForId(String id) {
		return SaltUtil.getIdvidModulo(id, EnvUtil.getIdrepoSaltKeyLength());
	}

	public int getSaltKeyForHashOfId(String id) {
		return SaltUtil.getIdvidHashModulo(id, EnvUtil.getIdrepoSaltKeyLength());
	}

	/* ------------------- Cache Eviction ------------------- */

	@Scheduled(
			initialDelayString = "${" + IDREPO_CACHE_UPDATE_INTERVAL + ":" + CACHE_UPDATE_DEFAULT_INTERVAL + "}",
			fixedDelayString = "${" + IDREPO_CACHE_UPDATE_INTERVAL + ":" + CACHE_UPDATE_DEFAULT_INTERVAL + "}"
	)
	public void evictIdAttributeCacheAtInterval() {
		Cache cache = cacheManager.getCache("id_attributes");
		if (cache != null) {
			cache.clear();
		}
	}
}
