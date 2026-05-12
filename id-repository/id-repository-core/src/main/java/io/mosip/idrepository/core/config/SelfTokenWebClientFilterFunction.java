package io.mosip.idrepository.core.config;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;

import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterConstant;
import io.mosip.kernel.auth.defaultadapter.constant.AuthAdapterErrorCode;
import io.mosip.kernel.auth.defaultadapter.exception.AuthAdapterException;
import io.mosip.kernel.auth.defaultadapter.helper.TokenHelper;
import io.mosip.kernel.auth.defaultadapter.helper.TokenValidationHelper;
import io.mosip.kernel.auth.defaultadapter.model.TokenHolder;
import reactor.core.publisher.Mono;

/**
 * Fixed replacement for {@code SelfTokenExchangeFilterFunction} from kernel-auth-adapter.
 *
 * <p>The kernel version's retry path (after a 401 response) mutates
 * {@code request.headers()} directly, which throws
 * {@link UnsupportedOperationException} in Spring Boot 3.x because
 * {@code ClientRequest.headers()} returns a {@link org.springframework.http.ReadOnlyHttpHeaders}.
 *
 * <p>This implementation uses {@code ClientRequest.from(request)} in both the
 * initial attempt and the retry path, which is the correct immutable approach.
 */
public class SelfTokenWebClientFilterFunction implements ExchangeFilterFunction {

    private static final Logger LOGGER = LoggerFactory.getLogger(SelfTokenWebClientFilterFunction.class);

    private final String clientID;
    private final String clientSecret;
    private final String appID;
    private final TokenHolder<String> cachedToken;
    private final TokenHelper tokenHelper;
    private final TokenValidationHelper tokenValidationHelper;
    private final WebClient webClient;

    public SelfTokenWebClientFilterFunction(Environment environment, WebClient webClient,
            TokenHolder<String> cachedToken, TokenHelper tokenHelper,
            TokenValidationHelper tokenValidationHelper, String appName) {
        this.clientID = environment.getProperty("mosip.iam.adapter.clientid." + appName,
                environment.getProperty("mosip.iam.adapter.clientid", ""));
        this.clientSecret = environment.getProperty("mosip.iam.adapter.clientsecret." + appName,
                environment.getProperty("mosip.iam.adapter.clientsecret", ""));
        this.appID = environment.getProperty("mosip.iam.adapter.appid." + appName,
                environment.getProperty("mosip.iam.adapter.appid", ""));
        this.cachedToken = cachedToken;
        this.webClient = webClient;
        this.tokenHelper = tokenHelper;
        this.tokenValidationHelper = tokenValidationHelper;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        if (cachedToken.getToken() == null) {
            String authToken = tokenHelper.getClientToken(clientID, clientSecret, appID, webClient);
            if (Objects.isNull(authToken)) {
                LOGGER.error("Failed to obtain self-token using clientid/secret");
                throw new AuthAdapterException(
                        AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorCode(),
                        AuthAdapterErrorCode.SELF_AUTH_TOKEN_NULL.getErrorMessage());
            }
            cachedToken.setToken(authToken);
        }

        ClientRequest firstAttempt = ClientRequest.from(request)
                .header(AuthAdapterConstant.AUTH_HEADER_COOKIE,
                        AuthAdapterConstant.AUTH_HEADER + cachedToken.getToken())
                .build();

        ClientResponse response = next.exchange(firstAttempt).block();

        if (response != null && response.statusCode() != HttpStatus.UNAUTHORIZED) {
            return Mono.just(response);
        }

        // Token was rejected — refresh it once under a lock, then retry.
        synchronized (this) {
            if (!isTokenValid(cachedToken.getToken())) {
                String refreshed = tokenHelper.getClientToken(clientID, clientSecret, appID, webClient);
                cachedToken.setToken(refreshed);
            }
        }

        // Build a new ClientRequest with updated cookie — never mutate the original.
        List<String> existingCookies = request.headers().get(AuthAdapterConstant.AUTH_HEADER_COOKIE);
        List<String> filteredCookies = (existingCookies != null)
                ? existingCookies.stream()
                        .filter(c -> !c.contains(AuthAdapterConstant.AUTH_HEADER))
                        .collect(Collectors.toList())
                : null;

        ClientRequest retryReq = ClientRequest.from(request)
                .headers(h -> {
                    h.remove(AuthAdapterConstant.AUTH_HEADER_COOKIE);
                    if (filteredCookies != null && !filteredCookies.isEmpty()) {
                        h.addAll(AuthAdapterConstant.AUTH_HEADER_COOKIE, filteredCookies);
                    }
                    h.add(AuthAdapterConstant.AUTH_HEADER_COOKIE,
                            AuthAdapterConstant.AUTH_HEADER + cachedToken.getToken());
                })
                .build();

        return next.exchange(retryReq);
    }

    private boolean isTokenValid(String authToken) {
        return Objects.nonNull(tokenValidationHelper.doOnlineTokenValidation(authToken, webClient));
    }
}
