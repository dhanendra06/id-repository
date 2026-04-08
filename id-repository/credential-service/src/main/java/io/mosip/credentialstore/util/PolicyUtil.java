package io.mosip.credentialstore.util;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.credentialstore.constants.ApiName;
import io.mosip.credentialstore.constants.LoggerFileConstant;
import io.mosip.credentialstore.dto.PartnerCredentialTypePolicyDto;
import io.mosip.credentialstore.dto.PartnerExtractorResponse;
import io.mosip.credentialstore.dto.PartnerExtractorResponseDto;
import io.mosip.credentialstore.dto.PolicyManagerResponseDto;
import io.mosip.credentialstore.exception.ApiNotAccessibleException;
import io.mosip.credentialstore.exception.PartnerException;
import io.mosip.credentialstore.exception.PolicyException;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.exception.ServiceError;
import io.mosip.kernel.core.logger.spi.Logger;


@Component
public class PolicyUtil {


	private static final String PARTNER_EXTRACTOR_FORMATS = "PARTNER_EXTRACTOR_FORMATS";

	private static final String DATASHARE_POLICIES = "DATASHARE_POLICIES";

	/** The rest template. */
	@Autowired
	RestUtil restUtil;

	private static final Logger LOGGER = IdRepoLogger.getLogger(PolicyUtil.class);

	/** The mapper. */
	@Autowired
	private ObjectMapper mapper;

	@Autowired
	Utilities utilities;
	
	@Autowired
	private CacheManager cacheManager;

	// Thread-safe in-JVM caches — act as a reliable fallback in case Spring's
	// @Cacheable proxy is not applied (e.g., self-invocation or proxy misconfiguration).
	// Cleared by clearDataSharePoliciesCache() / clearPartnerExtractorFormatsCache()
	// which are called by the scheduler in PartnerCacheUpdatingSchedulerConfig.
	private final ConcurrentHashMap<String, PartnerCredentialTypePolicyDto> policyMap = new ConcurrentHashMap<>();

	// Optional wrapper allows caching absent responses (PMS_PRT_064) without ambiguity with null.
	private final ConcurrentHashMap<String, Optional<PartnerExtractorResponse>> extractorMap = new ConcurrentHashMap<>();

	// Per-key lock objects — prevent thundering herd: only one thread fetches per key on cache miss.
	private final ConcurrentHashMap<String, Object> policyKeyLocks = new ConcurrentHashMap<>();
	private final ConcurrentHashMap<String, Object> extractorKeyLocks = new ConcurrentHashMap<>();

	@Cacheable(cacheNames = DATASHARE_POLICIES, key = "{ #credentialType, #subscriberId }")
	public PartnerCredentialTypePolicyDto getPolicyDetail(String credentialType, String subscriberId, String requestId)
			throws PolicyException, ApiNotAccessibleException {

		String policyMapKey = credentialType + " " + subscriberId;
		PartnerCredentialTypePolicyDto cached = policyMap.get(policyMapKey);
		if (cached != null) {
			return cached;
		}
		// Per-key lock: only one thread fetches from the API for a given policy key.
		// Other threads wait and then get the result from policyMap on the second check.
		Object keyLock = policyKeyLocks.computeIfAbsent(policyMapKey, k -> new Object());
		synchronized (keyLock) {
			cached = policyMap.get(policyMapKey);
			if (cached != null) {
				return cached;
			}
			try {
				LOGGER.debug(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(),
						requestId,
						"started fetching the policy data");
				Map<String, String> pathsegments = new HashMap<>();
				pathsegments.put("partnerId", subscriberId);
				pathsegments.put("credentialType", credentialType);
				String responseString = restUtil.getApi(ApiName.PARTNER_POLICY, pathsegments, String.class);

				PolicyManagerResponseDto responseObject = mapper.readValue(responseString,
						PolicyManagerResponseDto.class);
				if (responseObject != null && responseObject.getErrors() != null && !responseObject.getErrors().isEmpty()) {
					ServiceError error = responseObject.getErrors().get(0);
					throw new PolicyException(error.getMessage());
				}
				PartnerCredentialTypePolicyDto policyResponseDto = responseObject != null ? responseObject.getResponse() : null;
				if (policyResponseDto != null) {
					policyMap.put(policyMapKey, policyResponseDto);
				}
				LOGGER.info(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(),
						requestId,
						"Fetched policy details successfully");
				LOGGER.debug(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
						"ended fetching the policy data");
				return policyResponseDto;

			} catch (IOException e) {
				LOGGER.error(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
						"error with error message" + ExceptionUtils.getStackTrace(e));
				throw new PolicyException(e);
			} catch (Exception e) {
				LOGGER.error(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
						"error with error message" + ExceptionUtils.getStackTrace(e));
				if (e.getCause() instanceof HttpClientErrorException) {
					HttpClientErrorException httpClientException = (HttpClientErrorException) e.getCause();
					throw new ApiNotAccessibleException(httpClientException.getResponseBodyAsString());
				} else if (e.getCause() instanceof HttpServerErrorException) {
					HttpServerErrorException httpServerException = (HttpServerErrorException) e.getCause();
					throw new ApiNotAccessibleException(httpServerException.getResponseBodyAsString());
				} else {
					throw new PolicyException(e);
				}
			}
		}

	}


	@Cacheable(cacheNames = PARTNER_EXTRACTOR_FORMATS, key = "{ #subscriberId, #policyId }")
	public PartnerExtractorResponse getPartnerExtractorFormat(String policyId, String subscriberId, String requestId)
			throws ApiNotAccessibleException, PartnerException {
		LOGGER.debug(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
				"started fetching the partner extraction policy data");
		String extractorKey = policyId + " " + subscriberId;
		Optional<PartnerExtractorResponse> cachedOptional = extractorMap.get(extractorKey);
		if (cachedOptional != null) {
			return cachedOptional.orElse(null);
		}
		// Per-key lock: only one thread fetches from the API for a given extractor key.
		Object keyLock = extractorKeyLocks.computeIfAbsent(extractorKey, k -> new Object());
		synchronized (keyLock) {
			cachedOptional = extractorMap.get(extractorKey);
			if (cachedOptional != null) {
				return cachedOptional.orElse(null);
			}
			try {
				Map<String, String> pathsegments = new HashMap<>();
				pathsegments.put("partnerId", subscriberId);
				pathsegments.put("policyId", policyId);
				String responseString = restUtil.getApi(ApiName.PARTNER_EXTRACTION_POLICY, pathsegments, String.class);
				mapper.configure(DeserializationFeature.ACCEPT_SINGLE_VALUE_AS_ARRAY, true);
				PartnerExtractorResponseDto responseObject = mapper.readValue(responseString,
						PartnerExtractorResponseDto.class);
				if (responseObject != null && responseObject.getErrors() != null && !responseObject.getErrors().isEmpty()) {
					ServiceError error = responseObject.getErrors().get(0);
					if (error.getErrorCode().equalsIgnoreCase("PMS_PRT_064")) {
						// Cache the absence so we don't re-fetch on every request
						extractorMap.put(extractorKey, Optional.empty());
						return null;
					} else {
						LOGGER.info(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
								error.getMessage());
						throw new PartnerException(error.getMessage());
					}
				}
				PartnerExtractorResponse partnerExtractorResponse = responseObject != null ? responseObject.getResponse() : null;
				extractorMap.put(extractorKey, Optional.ofNullable(partnerExtractorResponse));
				LOGGER.info(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
						"Fetched partner extraction policy details successfully");
				LOGGER.debug(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
						"ended fetching the policy data");
				return partnerExtractorResponse;
			} catch (Exception e) {
				LOGGER.error(IdRepoSecurityManager.getUser(), LoggerFileConstant.REQUEST_ID.toString(), requestId,
						"error with error message" + ExceptionUtils.getStackTrace(e));
				if (e.getCause() instanceof HttpClientErrorException) {
					HttpClientErrorException httpClientException = (HttpClientErrorException) e.getCause();
					throw new ApiNotAccessibleException(httpClientException.getResponseBodyAsString());
				} else if (e.getCause() instanceof HttpServerErrorException) {
					HttpServerErrorException httpServerException = (HttpServerErrorException) e.getCause();
					throw new ApiNotAccessibleException(httpServerException.getResponseBodyAsString());
				} else {
					throw new PartnerException(e);
				}
			}
		}

	}
	
	public void clearDataSharePoliciesCache() {
		Cache cache = cacheManager.getCache(DATASHARE_POLICIES);
		if (cache != null)
			cache.clear();
		policyMap.clear();
		LOGGER.info(IdRepoSecurityManager.getUser(), this.getClass().getSimpleName(), "clearDataSharePoliciesCache",
				DATASHARE_POLICIES + " cache cleared");
	}

	public void clearPartnerExtractorFormatsCache() {
		Cache cache = cacheManager.getCache(PARTNER_EXTRACTOR_FORMATS);
		if (cache != null)
			cache.clear();
		extractorMap.clear();
		LOGGER.info(IdRepoSecurityManager.getUser(), this.getClass().getSimpleName(),
				"clearPartnerExtractorFormatsCache", PARTNER_EXTRACTOR_FORMATS + " cache cleared");
	}
	
}
