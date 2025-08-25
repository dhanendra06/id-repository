package io.mosip.idrepository.core.helper;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.mosip.idrepository.core.builder.AuditRequestBuilder;
import io.mosip.idrepository.core.builder.RestRequestBuilder;
import io.mosip.idrepository.core.constant.AuditEvents;
import io.mosip.idrepository.core.constant.AuditModules;
import io.mosip.idrepository.core.constant.IdType;
import io.mosip.idrepository.core.constant.RestServicesConstants;
import io.mosip.idrepository.core.dto.AuditRequestDTO;
import io.mosip.idrepository.core.dto.AuditResponseDTO;
import io.mosip.idrepository.core.dto.RestRequestDTO;
import io.mosip.idrepository.core.exception.IdRepoDataValidationException;
import io.mosip.idrepository.core.exception.IdRepoExceptionHandler;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.core.exception.ExceptionUtils;
import io.mosip.kernel.core.http.RequestWrapper;
import io.mosip.kernel.core.logger.spi.Logger;

/**
 * Asynchronous Audit Helper for IdRepo.
 * Sends audit events to the audit service without blocking main processing.
 */
@Component
public class AuditHelper {

	/** Logger */
	private static final Logger mosipLogger = IdRepoLogger.getLogger(AuditHelper.class);

	/** Rest helper */
	@Autowired
	private RestHelper restHelper;

	/** Builders */
	@Autowired
	private AuditRequestBuilder auditBuilder;

	@Autowired
	private RestRequestBuilder restBuilder;

	@Autowired
	private IdRepoSecurityManager securityManager;

	@Autowired
	private ObjectMapper mapper;

	/**
	 * Send audit asynchronously.
	 */
	@Async("auditExecutor") // Optional: use dedicated executor if configured
	public void audit(AuditModules module, AuditEvents event, String id, IdType idType, String desc) {
		try {
			String requestId = (id != null) ? securityManager.hash(id.getBytes()) : null;

			RequestWrapper<AuditRequestDTO> auditRequest = auditBuilder.buildRequest(
					module, event, requestId, idType, desc);

			RestRequestDTO restRequest = restBuilder.buildRequest(
					RestServicesConstants.AUDIT_MANAGER_SERVICE,
					auditRequest,
					AuditResponseDTO.class
			);

			restHelper.requestAsync(restRequest)
					.exceptionally(ex -> {
						mosipLogger.error(IdRepoSecurityManager.getUser(), "AuditHelper", "audit",
								"Async audit failed: " + ExceptionUtils.getStackTrace(ex));
						return null;
					});

		} catch (IdRepoDataValidationException e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(), "AuditHelper", "audit",
					"Validation exception: " + ExceptionUtils.getStackTrace(e));
		} catch (Exception e) {
			mosipLogger.error(IdRepoSecurityManager.getUser(), "AuditHelper", "audit",
					"Unexpected exception: " + ExceptionUtils.getStackTrace(e));
		}
	}

	/**
	 * Audit error scenarios asynchronously.
	 */
	@Async("auditExecutor")
	public void auditError(AuditModules module, AuditEvents event, String id, IdType idType, Throwable e) {
		try {
			String errorDetails = mapper.writeValueAsString(IdRepoExceptionHandler.getAllErrors(e));
			this.audit(module, event, id, idType, errorDetails);
		} catch (JsonProcessingException ex) {
			mosipLogger.error(IdRepoSecurityManager.getUser(), "AuditHelper", "auditError",
					"Failed to serialize error details: " + ExceptionUtils.getStackTrace(ex));
		}
	}
}
