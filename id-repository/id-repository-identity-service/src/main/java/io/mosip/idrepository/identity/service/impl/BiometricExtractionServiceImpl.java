package io.mosip.idrepository.identity.service.impl;

import static io.mosip.idrepository.core.constant.IdRepoConstants.DOT;
import static io.mosip.idrepository.core.constant.IdRepoConstants.EXTRACTION_FORMAT_QUERY_PARAM_SUFFIX;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.BIO_EXTRACTION_ERROR;
import static io.mosip.idrepository.core.constant.IdRepoErrorConstants.UNKNOWN_ERROR;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import io.mosip.commons.khazana.exception.ObjectStoreAdapterException;
import io.mosip.idrepository.core.dto.BioExtractRequestDTO;
import io.mosip.idrepository.core.dto.BioExtractResponseDTO;
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
 * The Class BiometricExtractionServiceImpl.
 *
 * @author Loganathan Sekar
 */
@Service
public class BiometricExtractionServiceImpl implements BiometricExtractionService {

	private static final String EXTRACT_TEMPLATE = "extractTemplate";
	private static final String FORMAT_FLAG_SUFFIX = ".format";
	private static final Logger mosipLogger = IdRepoLogger.getLogger(BiometricExtractionServiceImpl.class);

	@Autowired
	private ObjectStoreHelper objectStoreHelper;

	@Autowired
	private BioExtractionHelper bioExractionHelper;

	@Autowired
	private CbeffUtil cbeffUtil;

	@Async("withSecurityContext")
	public CompletableFuture<List<BIR>> extractTemplate(String uinHash, String fileName,
														String extractionType, String extractionFormat, List<BIR> birsForModality) throws IdRepoAppException {

		long startTime = System.currentTimeMillis();

		String extractionFileName = fileName.split("\\.")[0] + DOT + getModalityForFormat(extractionType) + DOT + extractionFormat;

		try {
			// Step 1: Check if extracted template already exists
			if (objectStoreHelper.biometricObjectExists(uinHash, extractionFileName)) {
				logInfo("RETURNING EXISTING EXTRACTED BIOMETRICS FOR FORMAT", extractionType, extractionFormat);

				long startRead = System.currentTimeMillis();
				byte[] xmlBytes = objectStoreHelper.getBiometricObject(uinHash, extractionFileName);
				List<BIR> existingBirs = cbeffUtil.getBIRDataFromXML(xmlBytes);
				logTime("Time taken to read and parse existing BIRs", startRead);

				logTime("Total time (cache hit)", startTime);
				return CompletableFuture.completedFuture(existingBirs);
			}
		} catch (ObjectStoreAdapterException e) {
			logError("Error checking or reading object store", e);
		} catch (Exception e) {
            throw new RuntimeException(e);
        }

        try {
			logInfo("EXTRACTING BIOMETRICS FOR FORMAT", extractionType, extractionFormat);

			Map<String, String> formatFlag = Map.of(getFormatFlag(extractionType), extractionFormat);

			long extractionStart = System.currentTimeMillis();
			List<BIR> extractedBiometrics = extractBiometricTemplate(formatFlag, birsForModality);
			logTime("Biometric extraction time", extractionStart);

			// Step 2: Store extracted data if present
			if (!extractedBiometrics.isEmpty()) {
				long writeStart = System.currentTimeMillis();
				byte[] xml = cbeffUtil.createXML(extractedBiometrics);
				objectStoreHelper.putBiometricObject(uinHash, extractionFileName, xml);
				logTime("Time to serialize and store extracted BIRs", writeStart);
			}

			logTime("Total extraction time", startTime);
			return CompletableFuture.completedFuture(extractedBiometrics);
		} catch (BiometricExtractionException e) {
			logError("BiometricExtractionException occurred", e);
			throw new IdRepoAppException(BIO_EXTRACTION_ERROR, e);
		} catch (Exception e) {
			logError("Unexpected exception during biometric extraction", e);
			throw new IdRepoAppException(UNKNOWN_ERROR, e);
		}
	}

	private List<BIR> extractBiometricTemplate(Map<String, String> extractionFormats, List<BIR> birs)
			throws BiometricExtractionException {

		logDebug("INVOKING BIOMETRIC EXTRACTION FOR THE FORMAT", extractionFormats);

		BioExtractRequestDTO bioExtractReq = new BioExtractRequestDTO();
		bioExtractReq.setBiometrics(birs);
		bioExtractReq.setExtractionFormats(extractionFormats);

		BioExtractResponseDTO bioExtractResponseDTO = extractBiometrics(bioExtractReq);
		return bioExtractResponseDTO.getExtractedBiometrics();
	}

	private BioExtractResponseDTO extractBiometrics(BioExtractRequestDTO request)
			throws BiometricExtractionException {

		List<BIR> encodedExtractedBiometrics = doBioExtraction(request.getBiometrics(), request.getExtractionFormats());

		BioExtractResponseDTO response = new BioExtractResponseDTO();
		response.setExtractedBiometrics(encodedExtractedBiometrics);
		return response;
	}

	private List<BIR> doBioExtraction(List<BIR> birs, Map<String, String> extractionFormats)
			throws BiometricExtractionException {
		return bioExractionHelper.extractTemplates(birs, extractionFormats);
	}

	private String getFormatFlag(String formatQueryParam) {
		return formatQueryParam.replace(EXTRACTION_FORMAT_QUERY_PARAM_SUFFIX, FORMAT_FLAG_SUFFIX);
	}

	private String getModalityForFormat(String formatQueryParam) {
		return formatQueryParam.replace(EXTRACTION_FORMAT_QUERY_PARAM_SUFFIX, "");
	}

	private void logTime(String message, long startTime) {
		mosipLogger.debug(IdRepoSecurityManager.getUser(), this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
				message + ": " + (System.currentTimeMillis() - startTime) + " ms");
	}

	private void logInfo(String message, String extractionType, String extractionFormat) {
		mosipLogger.info(IdRepoSecurityManager.getUser(), this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
				message + ": " + extractionType + " : " + extractionFormat);
	}

	private void logError(String message, Exception e) {
		mosipLogger.error(IdRepoSecurityManager.getUser(), this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
				message + ": " + e.getMessage(), e);
	}

	private void logDebug(String message, Object param) {
		mosipLogger.debug(IdRepoSecurityManager.getUser(), this.getClass().getSimpleName(), EXTRACT_TEMPLATE,
				message + ": " + param);
	}
}
