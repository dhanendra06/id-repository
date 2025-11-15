package io.mosip.idrepository.identity.test.helper;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import io.mosip.kernel.core.fsadapter.exception.FSAdapterException;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.WebApplicationContext;

import io.mosip.commons.khazana.spi.ObjectStoreAdapter;
import io.mosip.idrepository.core.constant.IdRepoErrorConstants;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.security.IdRepoSecurityManager;
import io.mosip.idrepository.core.util.EnvUtil;
import io.mosip.idrepository.identity.helper.ObjectStoreHelper;
@Ignore
@ContextConfiguration(classes = { TestContext.class, WebApplicationContext.class })
@RunWith(SpringRunner.class)
@WebMvcTest
@Import(EnvUtil.class)
@ActiveProfiles("test")
public class ObjectStoreHelperTest {

	@InjectMocks
	private ObjectStoreHelper helper;

	@Mock
	private ObjectStoreAdapter adapter;

	@Mock
	private IdRepoSecurityManager securityManager;

	@Before
	public void init() {
		ReflectionTestUtils.setField(helper, "objectStoreAdapterName", "objectStoreAdapterName");
		ReflectionTestUtils.setField(helper, "objectStoreAccountName", "dummyAccount");
		ReflectionTestUtils.setField(helper, "objectStoreBucketName", "dummyBucket");
		ReflectionTestUtils.setField(helper, "bioDataRefId", "bioRefId");
		ReflectionTestUtils.setField(helper, "demoDataRefId", "demoRefId");
		ReflectionTestUtils.setField(helper, "chunkSize", 2);
		when(adapter.exists(any(String.class), any(String.class), any(), any(), any(String.class)))
				.thenReturn(Boolean.TRUE);
		ApplicationContext ctxMock = mock(ApplicationContext.class);
		when(ctxMock.getBean("objectStoreAdapterName", ObjectStoreAdapter.class)).thenReturn(adapter);
		helper.setObjectStore(ctxMock);
	}
	@Test
	public void testDemographicObjectExists() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		assertTrue(helper.demographicObjectExists("", ""));
	}

	@Test
	public void testBiometricObjectExists() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		assertTrue(helper.biometricObjectExists("", ""));
	}

	@Test
	public void testPutDemographicObject() throws Exception {
		byte[] data = "abcd".getBytes(); // length 4, 2 chunks
		final List<byte[]> observedChunks = new LinkedList<>();
		when(securityManager.encrypt(any(byte[].class), any())).thenAnswer(invocation -> {
			byte[] chunk = invocation.getArgument(0);
			observedChunks.add(Arrays.copyOf(chunk, chunk.length));
			// Mark the encrypted chunk as "E"+original
			byte[] enc = new byte[chunk.length + 1];
			enc[0] = (byte) 'E';
			System.arraycopy(chunk, 0, enc, 1, chunk.length);
			return enc;
		});
		when(adapter.putObject(any(), any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);

		helper.putDemographicObject("hash", "refId", data);

		assertEquals(2, observedChunks.size());
		assertArrayEquals("ab".getBytes(), observedChunks.get(0));
		assertArrayEquals("cd".getBytes(), observedChunks.get(1));

		ArgumentCaptor<String> argCaptor = ArgumentCaptor.forClass(String.class);
		verify(adapter).putObject(any(), any(), any(), any(), argCaptor.capture(), any());
		assertEquals("hash/Demographics/refId", argCaptor.getValue());
	}

	@Test
	public void testPutBiometricObject() throws Exception {
		byte[] data = "1234".getBytes(); // 2 chunks
		AtomicInteger counter = new AtomicInteger(1); // make sure we've been called twice
		when(securityManager.encrypt(any(byte[].class), any())).thenAnswer(invocation -> {
			byte[] in = invocation.getArgument(0);
			int n = counter.getAndIncrement();
			// Add the chunk number as first byte, then data
			byte[] out = new byte[in.length + 1];
			out[0] = (byte) (n + '0');
			System.arraycopy(in, 0, out, 1, in.length);
			return out;
		});
		when(adapter.putObject(any(), any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);

		helper.putBiometricObject("hash", "refId", data);

		verify(securityManager, times(2)).encrypt(any(), any());
		ArgumentCaptor<String> argCaptor = ArgumentCaptor.forClass(String.class);
		verify(adapter).putObject(any(), any(), any(), any(), argCaptor.capture(), any());
		assertEquals("hash/Biometrics/refId", argCaptor.getValue());
	}

	@Test
	public void testPutObjectException() throws Exception {
		when(securityManager.encrypt(any(), any())).thenAnswer(invocation -> invocation.getArgument(0));
		when(adapter.putObject(any(), any(), any(), any(), any(), any()))
				.thenThrow(new FSAdapterException("FS_ERROR", "File storage access error"));
		try {
			helper.putDemographicObject("hash", "refId", "xy".getBytes());
			fail("Expected FSAdapterException");
		} catch (FSAdapterException thrown) {
			assertEquals("FS_ERROR", thrown.getErrorCode());
			assertEquals("File storage access error", thrown.getErrorText());
		}
	}

	@Test
	public void testGetDemographicObject() throws Exception {
		// We'll chunk "xyab" -> "xy","ab"
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		// Simulate per chunk decryption (e.g. uppercase all bytes)
		when(securityManager.decrypt(any(byte[].class), any())).thenAnswer(invocation -> {
			byte[] chunk = invocation.getArgument(0);
			for (int i = 0; i < chunk.length; i++) chunk[i] = (byte) Character.toUpperCase((char) chunk[i]);
			return chunk;
		});
		when(adapter.getObject(any(), any(), any(), any(), any()))
				.thenReturn(new ByteArrayInputStream("xyab".getBytes()));
		byte[] demographicObject = helper.getDemographicObject("hash", "refId");
		assertEquals("XYAB", new String(demographicObject));
	}

	@Test
	public void testGetBiometricObject() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		when(securityManager.decrypt(any(byte[].class), any())).thenAnswer(invocation -> {
			byte[] in = invocation.getArgument(0);
			for (int i = 0; i < in.length; i++) in[i] = (byte) (in[i] + 1); // increment ascii
			return in;
		});
		when(adapter.getObject(any(), any(), any(), any(), any()))
				.thenReturn(new ByteArrayInputStream("12ab".getBytes()));
		byte[] bioObject = helper.getBiometricObject("hash", "refId");
		assertEquals("23bc", new String(bioObject));
	}

	@Test
	public void testGetDemographicObjectNotFound() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.FALSE);
		try {
			helper.getDemographicObject("hash", "refId");
			fail("Expected IdRepoAppException");
		} catch (IdRepoAppException e) {
			assertEquals(IdRepoErrorConstants.FILE_NOT_FOUND.getErrorCode(), e.getErrorCode());
			assertEquals(IdRepoErrorConstants.FILE_NOT_FOUND.getErrorMessage(), e.getErrorText());
		}
	}

	@Test
	public void testGetBiometricObjectNotFound() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.FALSE);
		try {
			helper.getBiometricObject("hash", "refId");
			fail("Expected IdRepoAppException");
		} catch (IdRepoAppException e) {
			assertEquals(IdRepoErrorConstants.FILE_NOT_FOUND.getErrorCode(), e.getErrorCode());
			assertEquals(IdRepoErrorConstants.FILE_NOT_FOUND.getErrorMessage(), e.getErrorText());
		}
	}

	@Test
	public void testGetObjectException() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		when(securityManager.encrypt(any(), any())).thenAnswer(invocation -> invocation.getArgument(0));
		when(adapter.getObject(any(), any(), any(), any(), any()))
				.thenThrow(new FSAdapterException("FS_ERROR", "File storage access error"));
		try {
			helper.getDemographicObject("hash", "refId");
			fail("Expected FSAdapterException");
		} catch (FSAdapterException thrown) {
			assertEquals("FS_ERROR", thrown.getErrorCode());
			assertEquals("File storage access error", thrown.getErrorText());
		}
	}

	@Test
	public void testDeleteBiometricObject() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		when(adapter.deleteObject(any(), any(), any(), any(), any())).thenReturn(Boolean.TRUE);
		helper.deleteBiometricObject("hash", "refId");
		ArgumentCaptor<String> argCaptor = ArgumentCaptor.forClass(String.class);
		verify(adapter).deleteObject(any(), any(), any(), any(), argCaptor.capture());
		assertEquals("hash/Biometrics/refId", argCaptor.getValue());
	}

	@Test
	public void testDeleteBiometricObjectNotExists() throws Exception {
		when(adapter.exists(any(), any(), any(), any(), any())).thenReturn(Boolean.FALSE);
		helper.deleteBiometricObject("hash", "refId"); // Should not call deleteObject, no exception
		verify(adapter, never()).deleteObject(any(), any(), any(), any(), any());
	}
}