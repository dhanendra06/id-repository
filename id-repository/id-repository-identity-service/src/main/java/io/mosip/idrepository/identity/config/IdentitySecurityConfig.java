package io.mosip.idrepository.identity.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.web.reactive.function.client.WebClient;

import io.mosip.idrepository.core.config.SelfTokenWebClientFilterFunction;
import io.mosip.idrepository.core.helper.RestHelper;
import io.mosip.idrepository.core.manager.CredentialServiceManager;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;


@Configuration
public class IdentitySecurityConfig {

	/**
	 * A fixed replacement for the kernel {@code selfTokenWebClient} bean.
	 *
	 * <p>The kernel's {@code SelfTokenExchangeFilterFunction} tries to mutate
	 * {@code ClientRequest.headers()} directly on the 401 retry path, which
	 * throws {@link UnsupportedOperationException} in Spring Boot 3.x because
	 * those headers are read-only. {@link SelfTokenWebClientFilterFunction}
	 * applies the same token-management logic but always builds a new
	 * {@code ClientRequest} via {@code ClientRequest.from()} instead.
	 */
	@Bean("fixedSelfTokenWebClient")
	public WebClient fixedSelfTokenWebClient(
			@Qualifier("plainWebClient") WebClient plainWebClient,
			TokenHolder<String> cachedTokenObject,
			TokenHelper tokenHelper,
			TokenValidationHelper tokenValidationHelper,
			Environment environment) {
		String appName = environment.getProperty("spring.application.name", "");
		SelfTokenWebClientFilterFunction filter = new SelfTokenWebClientFilterFunction(
				environment, plainWebClient, cachedTokenObject, tokenHelper, tokenValidationHelper, appName);
		return WebClient.builder().filter(filter).build();
	}

	@Bean
	public RestHelper restHelperWithAuth(@Qualifier("fixedSelfTokenWebClient") WebClient webClient) {
		return new RestHelper(webClient);
	}

	@Bean
	public IdRepoSecurityManager securityManagerWithAuth(@Qualifier("fixedSelfTokenWebClient") WebClient webClient) {
		return new IdRepoSecurityManager(restHelperWithAuth(webClient));
	}

	@Bean
	public CredentialServiceManager credentialServiceManager(@Qualifier("fixedSelfTokenWebClient") WebClient webClient) {
		return new CredentialServiceManager(restHelperWithAuth(webClient));
	}

}
