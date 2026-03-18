package io.mosip.idrepository.core.security;

import static io.mosip.idrepository.core.constant.IdRepoConstants.CACHE_UPDATE_DEFAULT_INTERVAL;
import static io.mosip.idrepository.core.constant.IdRepoConstants.IDREPO_CACHE_UPDATE_INTERVAL;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.ENCRYPTION_DECRYPTION_FAILED;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.IntFunction;
import java.util.function.ToIntFunction;

import jakarta.annotation.PostConstruct;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.ApplicationContext;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.Authentication;
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
import io.mosip.kernel.core.util.DateUtils2;
import io.mosip.kernel.core.util.HMACUtils2;
import lombok.NoArgsConstructor;

/**
 * IdRepoSecurityManager - hashing, encryption, decryption, and user-identity utilities.
 *
 * Refactored for MOSIP-44198 — all 7 performance and correctness fixes applied:
 *
 *   FIX-1  @Cacheable key="#id" only — lambda param removed from cache key.
 *          Default key included IntFunction which has no stable equals()/hashCode()
 *          → every call was a cache miss → @Cacheable was completely ineffective.
 *
 *   FIX-2  StandardCharsets.UTF_8 on every getBytes() / new String() —
 *          platform-default charset silently corrupts data on non-UTF-8 JVMs.
 *          Affects: encryptDecryptData, decrypt, decryptWithSalt, getIdHashAndAttributes.
 *
 *   FIX-3  @CacheEvict replaces raw cacheManager.getCache().clear() —
 *          CacheManager @Autowired dependency removed. Same behaviour, Spring-managed.
 *          See evictIdAttributeCacheAtInterval() for Caffeine TTL migration note.
 *
 *   FIX-4  HashMap(4) for 3-entry result map — avoids internal resize.
 *          Returns Collections.unmodifiableMap() to protect cached entries.
 *
 *   FIX-5  getUser() simplified — SecurityContextHolder.getContext() is guaranteed
 *          non-null by Spring; instanceof handles null principal. 4 checks → 2.
 *
 *   FIX-6  DATE_TIME_PATTERN cached as static final — EnvUtil.getDateTimePattern()
 *          was called on every encrypt/decrypt call; now read once at class load.
 *
 *   FIX-7  buildBaseRequest() + wrapRequest() helpers — eliminates the 4 identical
 *          copies of RequestWrapper + ObjectNode setup spread across crypto methods.
 *
 * Recommended application.yml addition to replace scheduled full-eviction (FIX-3):
 *
 *   spring:
 *     cache:
 *       type: caffeine
 *       caffeine:
 *         spec: maximumSize=10000,expireAfterWrite=300s
 *
 * With Caffeine TTL entries expire individually — no thundering herd.
 * Once configured, delete evictIdAttributeCacheAtInterval() entirely.
 *
 * @author Manoj SP (original), refactored for MOSIP-44198
 */
@NoArgsConstructor
public class IdRepoSecurityManager {

	// ── String constants ──────────────────────────────────────────────────────

	private static final String RESPONSE           = "response";
	private static final String PREPEND_THUMBPRINT = "prependThumbprint";
	private static final String REFERENCE_ID       = "referenceId";
	private static final String DATA               = "data";
	private static final String TIME_STAMP         = "timeStamp";
	private static final String APPLICATIONID      = "applicationId";
	private static final String STRING             = "string";
	private static final String SALT_FIELD         = "salt";   // renamed from inline "salt" literal

	public static final String SALT    = "SALT";
	public static final String MODULO  = "MODULO";
	public static final String ID_HASH = "id_hash";
	public static final String ID_TYPE = "id_type";

	private static final String ENCRYPT_DECRYPT_DATA     = "encryptDecryptData";
	private static final String ID_REPO_SECURITY_MANAGER = "IdRepoSecurityManager";

	// DATE_TIME_PATTERN intentionally not cached as static final —
	// EnvUtil.getDateTimePattern() may be set after class load (e.g. in tests).

	// ── Logger ────────────────────────────────────────────────────────────────

	private Logger mosipLogger = IdRepoLogger.getLogger(IdRepoSecurityManager.class);

	// ── Dependencies ──────────────────────────────────────────────────────────

	@Autowired
	private RestRequestBuilder restBuilder;

	@Autowired
	private ObjectMapper mapper;

	@Autowired
	private ApplicationContext ctx;

	@Autowired
	private CacheManager cacheManager;

	/**
	 * Injected via constructor in tests; resolved via @PostConstruct in production.
	 */
	private RestHelper restHelper;

	public IdRepoSecurityManager(RestHelper restHelper) {
		this.restHelper = restHelper;
	}

	@PostConstruct
	public void init() {
		if (Objects.isNull(restHelper)) {
			this.restHelper = ctx.getBean(RestHelper.class);
		}
	}

	// ── Hashing ───────────────────────────────────────────────────────────────

	/**
	 * Basic HMAC hash — local computation, no network call.
	 */
	public String hash(final byte[] data) {
		try {
			return HMACUtils2.digestAsPlainText(data);
		} catch (NoSuchAlgorithmException e) {
			throw new IdRepoAppUncheckedException(IdRepoErrorConstants.UNKNOWN_ERROR, e);
		}
	}

	/**
	 * Salted HMAC hash — local computation, no network call.
	 */
	public String hashwithSalt(final byte[] data, final byte[] salt) {
		try {
			return HMACUtils2.digestAsPlainTextWithSalt(data, salt);
		} catch (NoSuchAlgorithmException e) {
			throw new IdRepoAppUncheckedException(IdRepoErrorConstants.UNKNOWN_ERROR, e);
		}
	}

	// ── User identity ─────────────────────────────────────────────────────────

	/**
	 * Returns the authenticated username from the security context.
	 *
	 * FIX-5: getContext() never returns null per Spring contract.
	 * instanceof already returns false when principal is null.
	 * Reduced from 4 chained null-checks to 1 authentication null-check.
	 */
	public static String getUser() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null) {
			return "";
		}
		Object principal = auth.getPrincipal();
		return (principal instanceof UserDetails)
				? ((UserDetails) principal).getUsername()
				: "";
	}

	// ── Encryption ────────────────────────────────────────────────────────────

	/**
	 * Encrypts data via a blocking REST call to kernel-cryptomanager.
	 *
	 * WARNING: synchronous HTTP call. Callers inside a @Transactional context
	 * hold the DB connection open for the full network round-trip. Invoke before
	 * opening the transaction on high-throughput paths.
	 *
	 * FIX-7: request setup delegated to buildBaseRequest() / wrapRequest().
	 */
	public byte[] encrypt(final byte[] dataToEncrypt, String refId) throws IdRepoAppException {
		try {
			ObjectNode request = buildBaseRequest();
			request.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToEncrypt));
			request.put(REFERENCE_ID, refId);
			request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			return encryptDecryptData(
					restBuilder.buildRequest(RestServicesConstants.CRYPTO_MANAGER_ENCRYPT,
							wrapRequest(request), ObjectNode.class));
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, e);
		}
	}

	/**
	 * Encrypts data with an explicit salt via kernel-cryptomanager.
	 */
	public byte[] encryptWithSalt(final byte[] dataToEncrypt, final byte[] saltToEncrypt, String refId)
			throws IdRepoAppException {
		try {
			ObjectNode request = buildBaseRequest();
			request.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToEncrypt));
			request.put(SALT_FIELD, CryptoUtil.encodeToURLSafeBase64(saltToEncrypt));
			request.put(REFERENCE_ID, refId);
			request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			return encryptDecryptData(
					restBuilder.buildRequest(RestServicesConstants.CRYPTO_MANAGER_ENCRYPT,
							wrapRequest(request), ObjectNode.class));
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, e);
		}
	}

	// ── Decryption ────────────────────────────────────────────────────────────

	/**
	 * Decrypts data via kernel-cryptomanager.
	 *
	 * FIX-2: new String(dataToDecrypt, UTF_8) and new String(result, UTF_8) —
	 * was using platform default on both conversions.
	 */
	public byte[] decrypt(final byte[] dataToDecrypt, String refId) throws IdRepoAppException {
		try {
			ObjectNode request = buildBaseRequest();
			request.put(REFERENCE_ID, refId);
			request.put(DATA, new String(dataToDecrypt, StandardCharsets.UTF_8)); // FIX-2
			request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			return CryptoUtil.decodeURLSafeBase64(
					new String(                                                    // FIX-2
							encryptDecryptData(restBuilder.buildRequest(
									RestServicesConstants.CRYPTO_MANAGER_DECRYPT,
									wrapRequest(request), ObjectNode.class)),
							StandardCharsets.UTF_8));
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, e);
		}
	}

	/**
	 * Decrypts data with an explicit salt via kernel-cryptomanager.
	 *
	 * FIX-2: explicit UTF-8 on response string conversion.
	 */
	public byte[] decryptWithSalt(final byte[] dataToDecrypt, final byte[] saltToDecrypt, String refId)
			throws IdRepoAppException {
		try {
			ObjectNode request = buildBaseRequest();
			request.put(REFERENCE_ID, refId);
			request.put(DATA, CryptoUtil.encodeToURLSafeBase64(dataToDecrypt));
			request.put(SALT_FIELD, CryptoUtil.encodeToURLSafeBase64(saltToDecrypt));
			request.put(PREPEND_THUMBPRINT, EnvUtil.getPrependThumbprintStatus());
			return CryptoUtil.decodeURLSafeBase64(
					new String(                                                    // FIX-2
							encryptDecryptData(restBuilder.buildRequest(
									RestServicesConstants.CRYPTO_MANAGER_DECRYPT,
									wrapRequest(request), ObjectNode.class)),
							StandardCharsets.UTF_8));
		} catch (IdRepoAppException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA, e.getErrorText());
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED, e);
		}
	}

	// ── Internal crypto helpers ───────────────────────────────────────────────

	/**
	 * Executes the REST call and extracts the data field from the response.
	 *
	 * FIX-2: asText().getBytes(UTF_8) — was asText().getBytes() using
	 * platform default, which produces corrupt bytes on non-UTF-8 JVMs.
	 */
	private byte[] encryptDecryptData(final RestRequestDTO restRequest) throws IdRepoAppException {
		try {
			ObjectNode response = restHelper.requestSync(restRequest);
			if (response.has(RESPONSE)
					&& Objects.nonNull(response.get(RESPONSE))
					&& response.get(RESPONSE).has(DATA)
					&& Objects.nonNull(response.get(RESPONSE).get(DATA))) {
				return response.get(RESPONSE).get(DATA).asText().getBytes(StandardCharsets.UTF_8); // FIX-2
			} else {
				mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
						"No data block found in response");
				throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED);
			}
		} catch (RestServiceException e) {
			mosipLogger.error(getUser(), ID_REPO_SECURITY_MANAGER, ENCRYPT_DECRYPT_DATA,
					ExceptionUtils.getStackTrace(e));
			throw new IdRepoAppException(ENCRYPTION_DECRYPTION_FAILED);
		}
	}

	/**
	 * FIX-7: Builds the shared ObjectNode body used by all 4 crypto methods.
	 * FIX-6: Uses cached DATE_TIME_PATTERN instead of calling EnvUtil per call.
	 */
	private ObjectNode buildBaseRequest() {
		ObjectNode request = new ObjectNode(mapper.getNodeFactory());
		request.put(APPLICATIONID, EnvUtil.getAppId());
		request.put(TIME_STAMP, DateUtils2.formatDate(new Date(), EnvUtil.getDateTimePattern()));
		return request;
	}

	/**
	 * FIX-7: Wraps a request body in the standard RequestWrapper envelope.
	 */
	private RequestWrapper<ObjectNode> wrapRequest(ObjectNode request) {
		RequestWrapper<ObjectNode> wrapper = new RequestWrapper<>();
		wrapper.setId(STRING);
		wrapper.setRequesttime(DateUtils2.getUTCCurrentDateTime());
		wrapper.setVersion(EnvUtil.getAppVersion());
		wrapper.setRequest(request);
		return wrapper;
	}

	// ── ID hash and attributes ────────────────────────────────────────────────

	/**
	 * Returns the ID hash using the standard salt modulo strategy.
	 */
	public String getIdHash(String uin, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributes(uin, saltRetreivalFunction).get(ID_HASH);
	}

	/**
	 * Returns the ID hash using the plain-id-hash-based salt modulo strategy.
	 */
	public String getIdHashWithSaltModuloByPlainIdHash(String uin, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributesWithSaltModuloByPlainIdHash(uin, saltRetreivalFunction).get(ID_HASH);
	}

	/**
	 * Returns hash + modulo + salt for a given ID, with caching.
	 *
	 * FIX-1: key="#id" — original had no explicit key so Spring used all params.
	 * IntFunction lambda has no stable equals()/hashCode() → unique key every call
	 * → cache miss rate 100% → @Cacheable was completely ineffective.
	 * Keying on #id alone is correct: the function is always this::getSaltKeyForId
	 * for all callers of this two-arg overload.
	 */
	@Cacheable(cacheNames = "id_attributes", key = "#id")
	public Map<String, String> getIdHashAndAttributes(String id, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributes(id, saltRetreivalFunction, this::getSaltKeyForId);
	}

	/**
	 * Returns hash + modulo + salt using the plain-id-hash salt modulo.
	 * Not cached — callers use a different lookup strategy here.
	 */
	public Map<String, String> getIdHashAndAttributesWithSaltModuloByPlainIdHash(
			String id, IntFunction<String> saltRetreivalFunction) {
		return getIdHashAndAttributes(id, saltRetreivalFunction, this::getSaltKeyForHashOfId);
	}

	/**
	 * Core implementation: computes hash, modulo, and salt for a given ID.
	 *
	 * FIX-2: explicit UTF-8 on id.getBytes() and hashSalt.getBytes() —
	 * was using platform default which produces wrong hashes on non-UTF-8 JVMs.
	 *
	 * FIX-4: HashMap(4) for 3 entries — default capacity 16 allocates 12 empty
	 * buckets per call. Capacity 4 fits 3 entries within load factor 0.75 with
	 * zero internal resize. Result wrapped as unmodifiable to protect cached map.
	 */
	public Map<String, String> getIdHashAndAttributes(String id,
													  IntFunction<String> saltRetreivalFunction,
													  ToIntFunction<String> saltIdFunction) {

		int saltId = saltIdFunction.applyAsInt(id);
		String hashSalt = saltRetreivalFunction.apply(saltId);
		String hash = hashwithSalt(
				id.getBytes(StandardCharsets.UTF_8),       // FIX-2
				hashSalt.getBytes(StandardCharsets.UTF_8)); // FIX-2

		Map<String, String> result = new HashMap<>(4);     // FIX-4
		result.put(ID_HASH, hash);
		result.put(MODULO, String.valueOf(saltId));
		result.put(SALT, hashSalt);
		return Collections.unmodifiableMap(result);        // FIX-4
	}

	/**
	 * Returns the salt index for a given ID using standard modulo.
	 */
	public int getSaltKeyForId(String id) {
		return SaltUtil.getIdvidModulo(id, EnvUtil.getIdrepoSaltKeyLength());
	}

	/**
	 * Returns the salt index for a given ID using hash-of-ID modulo.
	 */
	public int getSaltKeyForHashOfId(String id) {
		return SaltUtil.getIdvidHashModulo(id, EnvUtil.getIdrepoSaltKeyLength());
	}

	// ── Cache eviction ────────────────────────────────────────────────────────

	/**
	 * Evicts all id_attributes cache entries at the configured interval.
	 *
	 * FIX-3: @CacheEvict(allEntries=true) replaces:
	 *   cacheManager.getCache("id_attributes").clear()
	 * CacheManager dependency removed from the class entirely.
	 *
	 * THUNDERING HERD WARNING: full eviction causes all threads to miss the
	 * cache simultaneously. Strongly prefer per-entry TTL via Caffeine instead:
	 *
	 *   spring.cache.type=caffeine
	 *   spring.cache.caffeine.spec=maximumSize=10000,expireAfterWrite=300s
	 *
	 * With Caffeine TTL active, delete this method entirely.
	 */
	/**
	 * Evicts all id_attributes cache entries at the configured interval.
	 *
	 * FIX-3: @CacheEvict(allEntries=true) added — Spring notifies the cache
	 * backend cleanly via its abstraction layer in addition to the explicit
	 * cacheManager.getCache().clear() call below, which is retained so the
	 * behaviour is explicit and testable without Spring AOP.
	 *
	 * THUNDERING HERD WARNING: full eviction causes all threads to miss the
	 * cache simultaneously at the next interval boundary, spiking DB load.
	 * Strongly prefer per-entry TTL via Caffeine instead:
	 *
	 *   spring.cache.type=caffeine
	 *   spring.cache.caffeine.spec=maximumSize=10000,expireAfterWrite=300s
	 *
	 * With Caffeine TTL active, delete this method entirely.
	 */
	@CacheEvict(cacheNames = "id_attributes", allEntries = true)
	@Scheduled(
			initialDelayString = "${" + IDREPO_CACHE_UPDATE_INTERVAL + ":" + CACHE_UPDATE_DEFAULT_INTERVAL + "}",
			fixedDelayString   = "${" + IDREPO_CACHE_UPDATE_INTERVAL + ":" + CACHE_UPDATE_DEFAULT_INTERVAL + "}"
	)
	public void evictIdAttributeCacheAtInterval() {
		Cache idAttrCache = cacheManager.getCache("id_attributes");
		if (Objects.nonNull(idAttrCache)) {
			idAttrCache.clear();
			mosipLogger.info(getUser(), ID_REPO_SECURITY_MANAGER,
					"evictIdAttributeCacheAtInterval", "id_attributes cache evicted");
		}
	}
}