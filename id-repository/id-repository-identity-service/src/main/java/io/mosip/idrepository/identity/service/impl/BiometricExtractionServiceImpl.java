package io.mosip.idrepository.identity.service.impl;

import static io.mosip.idrepository.core.constant.IdRepoConstants.DOT;
import static io.mosip.idrepository.core.constant.IdRepoConstants.EXTRACTION_FORMAT_QUERY_PARAM_SUFFIX;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.BIO_EXTRACTION_ERROR;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.UNKNOWN_ERROR;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import io.mosip.commons.khazana.exception.ObjectStoreAdapterException;
import io.mosip.idrepository.core.exception.BiometricExtractionException;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.idrepository.core.spi.BiometricExtractionService;
import io.mosip.idrepository.identity.helper.BioExtractionHelper;
import io.mosip.idrepository.identity.helper.ObjectStoreHelper;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.core.logger.spi.Logger;

/**
 * BiometricExtractionServiceImpl
 *
 * Refactored for high-load performance and stability:
 *
 * 1.  Virtual threads via newVirtualThreadPerTaskExecutor — no pool sizing,
 *     no pinning on blocking I/O, ~1KB per thread vs ~1MB platform thread.
 *
 * 2.  @Async removed — CompletableFuture.supplyAsync() used directly so
 *     exceptions travel inside the future (not as UndeclaredThrowableException).
 *
 * 3.  In-flight deduplication — concurrent calls for the same
 *     uinHash+file+format share one CompletableFuture; no duplicate extraction.
 *
 * 4.  Safe filename parsing — lastIndexOf('.') instead of split() so filenames
 *     without an extension never produce a wrong cache key.
 *
 * 5.  Format string caching — getModalityForFormat / getFormatFlag results
 *     cached in ConcurrentHashMap; zero allocations after warmup.
 *
 * 6.  Wrapper DTO methods removed — bioExtractionHelper called directly,
 *     eliminating BioExtractRequestDTO / BioExtractResponseDTO allocations.
 *
 * 7.  xmlBytes scoped tightly — released as soon as parsing is done.
 */
@Service
public class BiometricExtractionServiceImpl implements BiometricExtractionService {

	// ── Constants ─────────────────────────────────────────────────────────────

	private static final String EXTRACT_TEMPLATE  = "extractTemplate";
	private static final String FORMAT_FLAG_SUFFIX = ".format";

	private static final Logger mosipLogger =
			IdRepoLogger.getLogger(BiometricExtractionServiceImpl.class);

	// ── Format-string caches (populated once per unique format at runtime) ────

	private static final ConcurrentHashMap<String, String> MODALITY_CACHE    = new ConcurrentHashMap<>();
	private static final ConcurrentHashMap<String, String> FORMAT_FLAG_CACHE = new ConcurrentHashMap<>();

	// ── In-flight deduplication map ───────────────────────────────────────────
	// Key: uinHash_fileName_extractionType_extractionFormat
	// Value: the single in-progress CompletableFuture shared by all callers
	// Removed from map via whenComplete so memory is never leaked.

	private final ConcurrentHashMap<String, CompletableFuture<List<BIR>>> inflightExtractions =
			new ConcurrentHashMap<>();

	// ── Dependencies ──────────────────────────────────────────────────────────

	@Autowired
	private ObjectStoreHelper objectStoreHelper;

	@Autowired
	private BioExtractionHelper bioExtractionHelper;

	@Autowired
	private CbeffUtil cbeffUtil;

	/**
	 * Virtual-thread executor injected from configuration.
	 * Defined in AsyncConfig as:
	 *
	 *   @Bean("bioExtractionExecutor")
	 *   public Executor bioExtractionExecutor() {
	 *       return Executors.newVirtualThreadPerTaskExecutor();
	 *   }
	 *
	 * Falls back to a local virtual-thread executor if the bean is absent
	 * (e.g. during unit tests).
	 */
	@Autowired(required = false)
	@Qualifier("bioExtractionExecutor")
	private Executor executor = Executors.newVirtualThreadPerTaskExecutor();

	// ── Public API ────────────────────────────────────────────────────────────

	/**
	 * Asynchronously extracts a biometric template, returning a shared
	 * CompletableFuture so concurrent calls for the same key do no duplicate work.
	 *
	 * @param uinHash           hash identifying the UIN bucket in object store
	 * @param fileName          original biometric file name (e.g. "bio.xml")
	 * @param extractionType    query-param-style format key (e.g. "finger.extractionFormat")
	 * @param extractionFormat  target format value  (e.g. "ISO19794_4_2011")
	 * @param birsForModality   parsed BIR list for the relevant modality
	 * @return CompletableFuture that completes with extracted BIRs,
	 *         or completes exceptionally with IdRepoAppException
	 */
	@Override
	public CompletableFuture<List<BIR>> extractTemplate(
			String uinHash,
			String fileName,
			String extractionType,
			String extractionFormat,
			List<BIR> birsForModality) {

		// Dedup key — uniquely identifies this extraction request
		String key = uinHash + "_" + fileName + "_" + extractionType + "_" + extractionFormat;

		return inflightExtractions.computeIfAbsent(key, k -> {
			CompletableFuture<List<BIR>> future = CompletableFuture.supplyAsync(
					() -> doExtract(uinHash, fileName, extractionType, extractionFormat, birsForModality),
					executor);

			// Two-arg remove: only evicts this exact future, never a newer one for the same key
			future.whenComplete((result, ex) -> inflightExtractions.remove(k, future));
			return future;
		});
	}

	// ── Private extraction logic ──────────────────────────────────────────────

	/**
	 * Core extraction logic executed on a virtual thread.
	 * Throws CompletionException (unchecked) so supplyAsync propagates it correctly.
	 */
	private List<BIR> doExtract(
			String uinHash,
			String fileName,
			String extractionType,
			String extractionFormat,
			List<BIR> birsForModality) {

		try {
			String extractionFileName = buildExtractionFileName(fileName, extractionType, extractionFormat);

			// ── Cache hit path ────────────────────────────────────────────────
			List<BIR> cached = tryLoadFromObjectStore(uinHash, extractionFileName);
			if (cached != null) {
				mosipLogger.info(IdRepoSecurityManager.getUser(),
						this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
						"Returning cached extraction for format: "
								+ extractionType + " : " + extractionFormat);
				return cached;
			}

			// ── Extraction path ───────────────────────────────────────────────
			mosipLogger.info(IdRepoSecurityManager.getUser(),
					this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
					"Extracting biometrics for format: "
							+ extractionType + " : " + extractionFormat);

			Map<String, String> formatFlag = Map.of(getFormatFlag(extractionType), extractionFormat);

			// Direct call — no BioExtractRequestDTO/ResponseDTO wrapper objects
			List<BIR> extractedBiometrics =
					bioExtractionHelper.extractTemplates(birsForModality, formatFlag);

			if (!extractedBiometrics.isEmpty()) {
				objectStoreHelper.putBiometricObject(
						uinHash, extractionFileName, cbeffUtil.createXML(extractedBiometrics));
			}

			return extractedBiometrics;

		} catch (BiometricExtractionException e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(),
					this.getClass().getSimpleName(), EXTRACT_TEMPLATE, e.getMessage());
			// Wrap in CompletionException so supplyAsync delivers it as ExecutionException
			throw new CompletionException(new IdRepoAppException(BIO_EXTRACTION_ERROR, e));

		} catch (IdRepoAppException e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(),
					this.getClass().getSimpleName(), EXTRACT_TEMPLATE, e.getMessage());
			throw new CompletionException(e);

		} catch (Exception e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(),
					this.getClass().getSimpleName(), EXTRACT_TEMPLATE, e.getMessage());
			throw new CompletionException(new IdRepoAppException(UNKNOWN_ERROR, e));
		}
	}

	/**
	 * Attempts to load pre-extracted biometrics from the object store.
	 * Returns null (not an exception) on any store failure so the caller
	 * falls through to live extraction — failure is logged, not fatal.
	 */
	private List<BIR> tryLoadFromObjectStore(String uinHash, String extractionFileName) {
		try {
			byte[] xmlBytes = objectStoreHelper.getBiometricObject(uinHash, extractionFileName);
			if (xmlBytes == null) return null;
			return cbeffUtil.getBIRDataFromXML(xmlBytes);

		} catch (ObjectStoreAdapterException|IdRepoAppException e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(),
					this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
					"Object store check failed, falling back to extraction: " + e.getMessage());
			return null;

        } catch (Exception e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(),
					this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
					"Object store check failed, falling back to extraction: " + e.getMessage());
        }
        return null;
    }

	// ── Filename helpers ──────────────────────────────────────────────────────

	/**
	 * Builds the extraction file name from the source file name.
	 * Uses lastIndexOf('.') instead of split() to handle:
	 *   - filenames with no extension  ("biofile"     → base = "biofile")
	 *   - filenames with multiple dots ("bio.v2.xml"  → base = "bio.v2")
	 */
	private String buildExtractionFileName(
			String fileName, String extractionType, String extractionFormat) {

		int dotIndex = fileName.lastIndexOf('.');
		String baseName = dotIndex > 0 ? fileName.substring(0, dotIndex) : fileName;
		return baseName + DOT + getModalityForFormat(extractionType) + DOT + extractionFormat;
	}

	// ── Cached format string transforms ──────────────────────────────────────

	/**
	 * Returns the modality string for a given format query param.
	 * Result is cached — zero String allocations after first call per unique param.
	 * Example: "finger.extractionFormat" → "finger"
	 */
	private String getModalityForFormat(String formatQueryParam) {
		return MODALITY_CACHE.computeIfAbsent(formatQueryParam,
				k -> k.replace(EXTRACTION_FORMAT_QUERY_PARAM_SUFFIX, ""));
	}

	/**
	 * Returns the format flag key for a given format query param.
	 * Result is cached — zero String allocations after first call per unique param.
	 * Example: "finger.extractionFormat" → "finger.format"
	 */
	private String getFormatFlag(String formatQueryParam) {
		return FORMAT_FLAG_CACHE.computeIfAbsent(formatQueryParam,
				k -> k.replace(EXTRACTION_FORMAT_QUERY_PARAM_SUFFIX, FORMAT_FLAG_SUFFIX));
	}
}
