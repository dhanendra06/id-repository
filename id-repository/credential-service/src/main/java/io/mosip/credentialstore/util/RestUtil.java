package io.mosip.credentialstore.util;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import io.mosip.credentialstore.constants.ApiName;
import io.mosip.idrepository.core.logger.IdRepoLogger;
import io.mosip.idrepository.core.util.EnvUtil;

public class RestUtil {

    @Autowired
    private EnvUtil environment;

	@Autowired
	@Qualifier("selfTokenWebClient")
	private WebClient webClient;

	@SuppressWarnings("unchecked")
	public <T> T postApi(ApiName apiName, List<String> pathsegments, String queryParamName, String queryParamValue,
			MediaType mediaType, Object requestType, Class<?> responseClass) throws Exception {
		  T result = null;
		String apiHostIpPort = environment.getProperty(apiName.name());
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
		IdRepoLogger.getLogger(RestUtil.class).debug(uriComponents.toUri().toString());
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

	@SuppressWarnings("unchecked")
	public <T> T getApi(ApiName apiName, Map<String, String>  pathsegments,
			Class<?> responseType) throws Exception {

		String apiHostIpPort = environment.getProperty(apiName.name());
		T result = null;
		UriComponentsBuilder builder = null;
		if (apiHostIpPort != null) {

			 builder = UriComponentsBuilder.fromUriString(apiHostIpPort);

			 URI urlWithPath = builder.build(pathsegments);

        try {
            result = (T) webClient.get()
                    .uri(urlWithPath)
                    .retrieve()
                    .bodyToMono(responseType)
                    .block();
        } catch (Exception e) {
        	throw new Exception(e);
        }

		}
		return result;
    }

	@SuppressWarnings("unchecked")
	public <T> T postApi(String url, List<String> pathsegments, String queryParamName, String queryParamValue,
			MediaType mediaType, Object requestType, Class<?> responseClass) throws Exception {
		T result = null;

		UriComponentsBuilder builder = null;
		if (url != null)
			builder = UriComponentsBuilder.fromUriString(url);
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
                    String contentType = "Content-Type";
                    if (!(headers.containsKey(contentType) && key.equals(contentType)))
                        headers.add(key, Objects.requireNonNull(httpHeader.get(key)).get(0));
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
