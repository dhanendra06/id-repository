package io.mosip.idrepository.core.security;

import static io.mosip.idrepository.core.constant.IdRepoConstants.CACHE_UPDATE_DEFAULT_INTERVAL;
import static io.mosip.idrepository.core.constant.IdRepoConstants.IDREPO_CACHE_UPDATE_INTERVAL;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.ENCRYPTION_DECRYPTION_FAILED;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Semaphore;
import java.util.function.IntFunction;
import java.util.function.ToIntFunction;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.mosip.idrepository.core.constant.IdRepoErrorConstants;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.exception.IdRepoAppUncheckedException;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.util.EnvUtil;
import io.mosip.idrepository.core.util.SaltUtil;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.logger.spi.Logger;
import io.mosip.kernel.core.util.CryptoUtil;
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.core.util.HMACUtils2;
import lombok.NoArgsConstructor;

/**
 * IdRepoSecurityManager - provides security related functionalities
 * such as hashing, encryption and decryption using kernel-cryptomanager
 * and providing user details.
 *
 * This version:
 * - Uses pooled WebClient (selfTokenWebClient) instead of RestTemplate/RestHelper
 * - Adds a concurrency gate via Semaphore to protect CPU & cryptomanager
 * - Remains fully backward compatible in behavior.
 */
@NoArgsConstructor
@Component
public class IdRepoSecurityManager {

	private static final String RESPONSE = "response";
	private static final String PREPEND_THUMBPRINT = "prependThumbprint";
	private static final String REFERENCE_ID = "referenceId";
	private static final String DATA = "data";
	private static final String TIME_STAMP = "timeStamp";
	private static final String APPLICATIONID = "applicationId";
	private static final String STRING = "string";

	public static final String SALT = "SALT";
	public static final String MODULO = "MODULO";
	public static final String ID_HASH = "id_hash";
	public static final String ID_TYPE = "id_type";

	private Logger mosipLogger = IdRepoLogger.getLogger(IdRepoSecurityManager.class);

	private static final String ENCRYPT_DECRYPT_DATA = "encryptDecryptData";
	private static final String ID_REPO_SECURITY_MANAGER = "IdRepoSecurityManager";

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private CacheManager cacheManager;

	@Autowired
	@Qualifier("selfTokenWebClient")
	private WebClient webClient;

	@Value("${mosip.crypto.application-id:${mosip.app-id:REGISTRATION}}")
	private String applicationId;

	@Value("${mosip.crypto.prepend-thumbprint:true}")
	private boolean prependThumbprint;

	@Value("${idrepo.crypto.encrypt-path:/v1/cryptomanager/encrypt}")
	private String encryptPath;

	@Value("${idrepo.crypto.decrypt-path:/v1/cryptomanager/decrypt}")
	private String decryptPath;

	/**
	 * Max concurrent cryptomanager calls allowed from this service.
	 * Protects 2 vCPU node from overload and OOM.
	 */
	@Value("${idrepo.crypto.max-concurrency:8}")
	private int maxCryptoConcurrency;

	private Semaphore cryptoSemaphore;

	@PostConstruct
	public void init() {
		if (cryptoSemaphore == null) {
			cryptoSemaphore = new Semaphore(maxCryptoConcurrency);
		}
	}

	/* ===================================================================== */
	/* ============================= HASHING ================================ */
	/* ===================================================================== */

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

	/* ===================================================================== */
	/* =========================== USER ID HELPERS ========================== */
	/* ===================================================================== */

	public static String getUser() {
		if (Objects.nonNull(SecurityContextHolder.getContext())
				&& Objects.nonNull(SecurityContextHolder.getContext().getAuthentication())
				&& Objects.nonNull(SecurityContextHolder.getContext().getAuthentication().getPrincipal())
				&& SecurityContextHolder.getContext().getAuthentication().getPrincipal() instanceof UserDetails) {
			return ((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal())
					.getUsername();
		} else {
			return "";
		}
	}

	/* ===================================================================== */
	/* ====================== ENCRYPT / DECRYPT (SYNC) ====================== */
	/* ===================================================================== */

	public byte[] encrypt(final byte[] dataToEncrypt, String refId) throws IdRepoAppException {
		try {
			ObjectNode baseRequest = buildBaseRequest();
			ObjectNode req = mapper.createObjectNode();
			req.put(APPLICATIONID, getAppId());
			req.put(TIME_STAMP, DateUtils2.formatDate(new Date(), EnvUtil.getDateTimePattern()));
			req.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToEncrypt));
			req.put(REFERENCE_ID, refId);
			req.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			baseRequest.set("request", req);

			return sendCryptoRequest(baseRequest, encryptPath);
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw e;
		}
	}

	public byte[] encryptWithSalt(final byte[] dataToEncrypt,
								  final byte[] saltToEncrypt,
								  String refId) throws IdRepoAppException {
		try {
			ObjectNode baseRequest = buildBaseRequest();
			ObjectNode req = mapper.createObjectNode();
			req.put(APPLICATIONID, getAppId());
			req.put(TIME_STAMP, DateUtils2.formatDate(new Date(), EnvUtil.getDateTimePattern()));
			req.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToEncrypt));
			req.put("salt", CryptoUtil.encodeToURLSafeBase64(saltToEncrypt));
			req.put(REFERENCE_ID, refId);
			req.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			baseRequest.set("request", req);

			return sendCryptoRequest(baseRequest, encryptPath);
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw e;
		}
	}

	public byte[] decrypt(final byte[] dataToDecrypt, String refId) throws IdRepoAppException {
		try {
			ObjectNode baseRequest = buildBaseRequest();
			ObjectNode req = mapper.createObjectNode();
			req.put(APPLICATIONID, getAppId());
			req.put(REFERENCE_ID, refId);
			req.put(TIME_STAMP, DateUtils2.formatDate(new Date(), EnvUtil.getDateTimePattern()));
			// original behavior: send raw string data (cipher text)
			req.put(DATA, new String(dataToDecrypt, StandardCharsets.UTF_8));
			req.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			baseRequest.set("request", req);

			byte[] resp = sendCryptoRequest(baseRequest, decryptPath);
			// original behavior: response.data is URL-safe base64 of plain bytes
			return CryptoUtil.decodeURLSafeBase64(new String(resp, StandardCharsets.UTF_8));
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw e;
		}
	}

	public byte[] decryptWithSalt(final byte[] dataToDecrypt,
								  final byte[] saltToDecrypt,
								  String refId) throws IdRepoAppException {
		try {
			ObjectNode baseRequest = buildBaseRequest();
			ObjectNode req = mapper.createObjectNode();
			req.put(APPLICATIONID, getAppId());
			req.put(REFERENCE_ID, refId);
			req.put(TIME_STAMP, DateUtils2.formatDate(new Date(), EnvUtil.getDateTimePattern()));
			req.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToDecrypt));
			req.put("salt", CryptoUtil.encodeToURLSafeBase64(saltToDecrypt));
			req.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			baseRequest.set("request", req);

			byte[] resp = sendCryptoRequest(baseRequest, decryptPath);
			return CryptoUtil.decodeURLSafeBase64(new String(resp, StandardCharsets.UTF_8));
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw e;
		}
	}

	/* ===================================================================== */
	/* ======================= COMMON CRYPTO HTTP ========================== */
	/* ===================================================================== */

	private ObjectNode buildBaseRequest() {
		ObjectNode baseRequest = mapper.createObjectNode();
		baseRequest.put("id", STRING);
		baseRequest.put("requesttime", DateUtils2.getUTCCurrentDateTimeString());
		baseRequest.put("version", EnvUtil.getAppVersion());
		return baseRequest;
	}

	private String getAppId() {
		String envId = EnvUtil.getAppId();
		if (envId != null && !envId.isBlank()) {
			return envId;
		}
		return applicationId;
	}

	/**
	 * Sends a crypto request using selfTokenWebClient and enforces concurrency limit.
	 *
	 * @param requestWrapper full request wrapper node
	 * @param path crypto endpoint path
	 * @return bytes of response.response.data (string bytes)
	 * @throws IdRepoAppException on any error
	 */
	private byte[] sendCryptoRequest(ObjectNode requestWrapper, String path) throws IdRepoAppException {
		boolean acquired = false;
		try {
			cryptoSemaphore.acquire();
			acquired = true;

			JsonNode response = webClient.post()
					.uri(path)
					.bodyValue(requestWrapper)
					.retrieve()
					.bodyToMono(JsonNode.class)
					.block(); // Blocking boundary, safe with semaphore

			if (response == null || !response.has(RESPONSE)) {
				mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
						"No response block found from cryptomanager");
				throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED);
			}

			JsonNode respNode = response.get(RESPONSE);
			if (respNode == null || !respNode.has(DATA) || respNode.get(DATA).isNull()) {
				mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
						"No data block found in cryptomanager response");
				throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED);
			}

			String dataText = respNode.get(DATA).asText();
			return dataText.getBytes(StandardCharsets.UTF_8);

		} catch (InterruptedException ie) {
			Thread.currentThread().interrupt();
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
					"Interrupted while calling cryptomanager: " + ExceptionUtils.getStackTrace(ie));
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, ie);
		} catch (Exception e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
					ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, e);
		} finally {
			if (acquired) {
				cryptoSemaphore.release();
			}
		}
	}

	/* ===================================================================== */
	/* =================== HASH + SALT / MODULO HELPERS ==================== */
	/* ===================================================================== */

	public String getIdHash(String uin, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributes(uin, saltRetreivalFunction).get(ID_HASH);
	}

	public String getIdHashWithSaltModuloByPlainIdHash(String uin, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributesWithSaltModuloByPlainIdHash(uin, saltRetreivalFunction).get(ID_HASH);
	}

	@Cacheable(cacheNames = "id_attributes")
	public Map<String, String> getIdHashAndAttributes(String id, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributes(id, saltRetreivalFunction, this::getSaltKeyForId);
	}

	public Map<String, String> getIdHashAndAttributesWithSaltModuloByPlainIdHash(
			String id, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributes(id, saltRetreivalFunction, this::getSaltKeyForHashOfId);
	}

	public Map<String, String> getIdHashAndAttributes(String id,
													  IntFunction<String> saltRetreivalFunction,
													  ToIntFunction<String> saltIdFunction) {
		Map<String, String> hashWithAttributes = new HashMap<>();
		int saltId = saltIdFunction.applyAsInt(id);
		String hashSalt = saltRetreivalFunction.apply(saltId);
		String hash = hashwithSalt(id.getBytes(StandardCharsets.UTF_8), hashSalt.getBytes(StandardCharsets.UTF_8));
		hashWithAttributes.put(ID_HASH, hash);
		hashWithAttributes.put(MODULO, String.valueOf(saltId));
		hashWithAttributes.put(SALT, hashSalt);
		return hashWithAttributes;
	}

	public int getSaltKeyForId(String id) {
		Integer saltKeyLength = EnvUtil.getIdrepoSaltKeyLength();
		return SaltUtil.getIdvidModulo(id, saltKeyLength);
	}

	public int getSaltKeyForHashOfId(String id) {
		Integer saltKeyLength = EnvUtil.getIdrepoSaltKeyLength();
		return SaltUtil.getIdvidHashModulo(id, saltKeyLength);
	}

	@Scheduled(
			initialDelayString = "${" + IDREPO_CACHE_UPDATE_INTERVAL + ":" + CACHE_UPDATE_DEFAULT_INTERVAL + "}",
			fixedDelayString = "${" + IDREPO_CACHE_UPDATE_INTERVAL + ":" + CACHE_UPDATE_DEFAULT_INTERVAL + "}")
	public void evictIdAttributeCacheAtInterval() {
		Cache idAttrCache = cacheManager.getCache("id_attributes");
		if (Objects.nonNull(idAttrCache)) {
			idAttrCache.clear();
		}
	}
}
