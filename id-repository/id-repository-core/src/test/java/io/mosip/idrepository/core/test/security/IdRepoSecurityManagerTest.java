package io.mosip.idrepository.core.test.security;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.mosip.idrepository.core.constant.IdRepoErrorConstants;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.kernel.core.util.CryptoUtil;
import reactor.core.publisher.Mono;

@RunWith(SpringRunner.class)
@WebMvcTest
@Import(ObjectMapper.class)
public class IdRepoSecurityManagerTest {

	@Mock
	WebClient webClient;

	@Mock
	WebClient.RequestBodyUriSpec bodySpec;  // RAW TYPE

	@Mock
	WebClient.RequestHeadersSpec headerSpec; // RAW TYPE (note: NO <?> !!)

	@Mock
	WebClient.ResponseSpec responseSpec;

	@InjectMocks
	IdRepoSecurityManager securityManager;

	@jakarta.annotation.Resource
	ObjectMapper mapper;

	@Before
	public void setup() {
		ReflectionTestUtils.setField(securityManager, "mapper", mapper);
		ReflectionTestUtils.setField(securityManager, "encryptPath", "/encrypt");
		ReflectionTestUtils.setField(securityManager, "decryptPath", "/decrypt");
		ReflectionTestUtils.setField(securityManager, "maxCryptoConcurrency", 5);
		ReflectionTestUtils.setField(securityManager, "webClient", webClient);
		securityManager.init();
	}

	/* ---------------- Helper mocks ------------------ */

	private void mockSuccess(String value) {
		ObjectNode root = mapper.createObjectNode();
		ObjectNode resp = mapper.createObjectNode();
		resp.put("data", value);
		root.set("response", resp);

		when(webClient.post()).thenReturn(bodySpec);
		when(bodySpec.uri(any(String.class))).thenReturn(bodySpec);
		when(bodySpec.bodyValue(any())).thenReturn(headerSpec);
		when(headerSpec.retrieve()).thenReturn(responseSpec);
		when(responseSpec.bodyToMono(JsonNode.class)).thenReturn(Mono.just(root));
	}

	private void mockFailure() {
		when(webClient.post()).thenReturn(bodySpec);
		when(bodySpec.uri(any(String.class))).thenReturn(bodySpec);
		when(bodySpec.bodyValue(any())).thenReturn(headerSpec);
		when(headerSpec.retrieve()).thenReturn(responseSpec);
		when(responseSpec.bodyToMono(JsonNode.class))
				.thenThrow(new RuntimeException("failure"));
	}

	/* ---------------- Tests ------------------ */

	@Test
	public void testEncryptSuccess() throws Exception {
		mockSuccess("encrypted");

		byte[] out = securityManager.encrypt("1".getBytes(), "RID");

		assertEquals("encrypted", new String(out, StandardCharsets.UTF_8));
	}

	@Test
	public void testDecryptSuccess() throws Exception {
		String plain = "hello";
		String b64 = CryptoUtil.encodeToURLSafeBase64(plain.getBytes());

		mockSuccess(b64);

		byte[] out = securityManager.decrypt("cipher".getBytes(), "RID");

		assertEquals(plain, new String(out, StandardCharsets.UTF_8));
	}

	@Test
	public void testEncryptFailure() {
		mockFailure();

		try {
			securityManager.encrypt("X".getBytes(), "RID");
		} catch (IdRepoAppException e) {
			assertEquals(IdRepoErrorConstants.ENCRYPTION_DECRYPTION_FAILED.getErrorCode(),
					e.getErrorCode());
		}
	}

	@Test
	public void testDecryptFailure() {
		mockFailure();

		try {
			securityManager.decrypt("X".getBytes(), "RID");
		} catch (IdRepoAppException e) {
			assertEquals(IdRepoErrorConstants.ENCRYPTION_DECRYPTION_FAILED.getErrorCode(),
					e.getErrorCode());
		}
	}

	@Test
	public void testDecryptNoData() {
		ObjectNode empty = mapper.createObjectNode();
		ObjectNode root = mapper.createObjectNode();
		root.set("response", empty);

		when(webClient.post()).thenReturn(bodySpec);
		when(bodySpec.uri(any(String.class))).thenReturn(bodySpec);
		when(bodySpec.bodyValue(any())).thenReturn(headerSpec);
		when(headerSpec.retrieve()).thenReturn(responseSpec);
		when(responseSpec.bodyToMono(JsonNode.class)).thenReturn(Mono.just(root));

		try {
			securityManager.decrypt("X".getBytes(), "RID");
		} catch (IdRepoAppException e) {
			assertEquals(IdRepoErrorConstants.ENCRYPTION_DECRYPTION_FAILED.getErrorCode(),
					e.getErrorCode());
		}
	}
}
