package io.mosip.credential.request.generator.util;

import io.mosip.credential.request.generator.constants.ApiName;
import io.mosip.idrepository.core.util.EnvUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

/**
 * @author Sowmya The Class RestUtil.
 */
@Component
public class RestUtil {

	private static final String CONTENT_TYPE = "Content-Type";

	@Autowired
	private EnvUtil environment;

	@Autowired
	@Qualifier("selfTokenWebClient")
	private WebClient webClient;

	/**
	 * Post api.
	 *
	 * @param                 <T> the generic type
	 * @param apiName         the api name
	 * @param pathsegments    the pathsegments
	 * @param queryParamName  the query param name
	 * @param queryParamValue the query param value
	 * @param mediaType       the media type
	 * @param requestType     the request type
	 * @param responseClass   the response class
	 * @return the t
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public <T> T postApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
			MediaType mediaType, Object requestType, Class<?> responseClass) throws Exception {
		T result = null;
		String apiHostIpPort = environment.getProperty(apiName.getServiceName());
		UriComponentsBuilder builder = null;
		if (apiHostIpPort != null)
			builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
		if (builder != null) {

			if (!((pathsegments == null) || (pathsegments.isEmpty()))) {
				for (String segment : pathsegments) {
					if (!((segment == null) || (("").equals(segment)))) {
						builder.pathSegment(segment);
					}
				}

			}
			if (!((queryParamName == null) || (("").equals(queryParamName)))) {
				String[] queryParamNameArr = queryParamName.split(",");
				String[] queryParamValueArr = queryParamValue.split(",");

				for (int i = 0; i < queryParamNameArr.length; i++) {
					builder.queryParam(queryParamNameArr[i], queryParamValueArr[i]);
				}
			}
			try {
				HttpHeaders headers = buildHeaders(requestType, mediaType);
				Object body = extractBody(requestType);
				WebClient.RequestHeadersSpec<?> headersSpec;
				if (body != null) {
					headersSpec = webClient.post()
							.uri(builder.toUriString())
							.headers(h -> h.addAll(headers))
							.bodyValue(body);
				} else {
					headersSpec = webClient.post()
							.uri(builder.toUriString())
							.headers(h -> h.addAll(headers));
				}
				result = (T) headersSpec.retrieve().bodyToMono(responseClass).block();
			} catch (Exception e) {
				throw new Exception(e);
			}
		}
		return result;
	}

	/**
	 * Gets the api.
	 *
	 * @param                 <T> the generic type
	 * @param apiName         the api name
	 * @param pathsegments    the pathsegments
	 * @param queryParamName  the query param name
	 * @param queryParamValue the query param value
	 * @param responseType    the response type
	 * @return the api
	 * @throws Exception
	 */
	@SuppressWarnings("unchecked")
	public <T> T getApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
			Class<?> responseType) throws Exception {

		String apiHostIpPort = environment.getProperty(apiName.name());
		T result = null;
		UriComponentsBuilder builder = null;
		UriComponents uriComponents = null;
		if (apiHostIpPort != null) {

			builder = UriComponentsBuilder.fromUriString(apiHostIpPort);
			if (!((pathsegments == null) || (pathsegments.isEmpty()))) {
				for (String segment : pathsegments) {
					if (!((segment == null) || (("").equals(segment)))) {
						builder.pathSegment(segment);
					}
				}

			}

			if (!((queryParamName == null) || (("").equals(queryParamName)))) {

				String[] queryParamNameArr = queryParamName.split(",");
				String[] queryParamValueArr = queryParamValue.split(",");
				for (int i = 0; i < queryParamNameArr.length; i++) {
					builder.queryParam(queryParamNameArr[i], queryParamValueArr[i]);
				}

			}
			uriComponents = builder.build(false).encode();
			try {
				result = (T) webClient.get()
						.uri(uriComponents.toUri())
						.retrieve()
						.bodyToMono(responseType)
						.block();
			} catch (Exception e) {
				throw new Exception(e);
			}
		}
		return result;
	}

	/**
	 * Builds headers for the WebClient request.
	 *
	 * @param requestType the request type
	 * @param mediaType   the media type
	 * @return the http headers
	 * @throws IOException Signals that an I/O exception has occurred.
	 */
	@SuppressWarnings("unchecked")
    private HttpHeaders buildHeaders(Object requestType, MediaType mediaType) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        if (mediaType != null) {
            headers.add("Content-Type", mediaType.toString());
        }
        if (requestType != null) {
            try {
                HttpEntity<Object> httpEntity = (HttpEntity<Object>) requestType;
                HttpHeaders httpHeader = httpEntity.getHeaders();
                for (String key : httpHeader.keySet()) {
                    if (!(headers.containsKey(CONTENT_TYPE) && key.equals(CONTENT_TYPE))) {
                        headers.add(key, Objects.requireNonNull(httpHeader.get(key)).get(0));
                    }
                }
            } catch (ClassCastException e) {
                // requestType is not HttpEntity, no additional headers to merge
            }
        }
        return headers;
    }

	@SuppressWarnings("unchecked")
    private Object extractBody(Object requestType) {
        if (requestType != null) {
            try {
                return ((HttpEntity<Object>) requestType).getBody();
            } catch (ClassCastException e) {
                return requestType;
            }
        }
        return null;
    }

}
