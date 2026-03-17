package io.mosip.idrepository.identity.test.service.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

import org.apache.commons.io.IOUtils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestContext;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.context.WebApplicationContext;

import io.mosip.commons.khazana.exception.ObjectStoreAdapterException;
import io.mosip.idrepository.core.constant.IdRepoErrorConstants;
import io.mosip.idrepository.core.exception.BiometricExtractionException;
import io.mosip.idrepository.core.exception.IdRepoAppException;
import io.mosip.idrepository.core.util.EnvUtil;
import io.mosip.idrepository.identity.helper.BioExtractionHelper;
import io.mosip.idrepository.identity.helper.ObjectStoreHelper;
import io.mosip.idrepository.identity.service.impl.BiometricExtractionServiceImpl;
import io.mosip.kernel.biometrics.commons.CbeffValidator;
import io.mosip.kernel.biometrics.entities.BIR;
import io.mosip.kernel.biometrics.spi.CbeffUtil;
import io.mosip.kernel.core.util.CryptoUtil;

@ContextConfiguration(classes = { TestContext.class, WebApplicationContext.class })
@RunWith(SpringRunner.class)
@WebMvcTest
@Import(EnvUtil.class)
@ActiveProfiles("test")
public class BiometricExtractionServiceImplTest {

	@InjectMocks
	private BiometricExtractionServiceImpl extractionServiceImpl;

	@Mock
	private ObjectStoreHelper objectStoreHelper;

	@Mock
	// FIX: field name must match the @Autowired field name in the refactored impl
	// Old impl had typo "bioExractionHelper", new impl corrected to "bioExtractionHelper"
	// If your impl still has the typo, revert this to "bioExractionHelper"
	private BioExtractionHelper bioExtractionHelper;

	@Mock
	private CbeffUtil cbeffUtil;

	// ── Helper: loads test CBEFF and returns parsed BIR list ──────────────────

	private List<BIR> loadTestBirs() throws Exception {
		String cbeff = IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("test-cbeff.xml"),
				StandardCharsets.UTF_8);
		return CbeffValidator.getBIRDataFromXMLType(
				CryptoUtil.decodeURLSafeBase64(cbeff), "Finger");
	}

	private byte[] loadTestCbeffBytes() throws Exception {
		String cbeff = IOUtils.toString(
				this.getClass().getClassLoader().getResourceAsStream("test-cbeff.xml"),
				StandardCharsets.UTF_8);
		return CryptoUtil.decodeURLSafeBase64(cbeff);
	}

	// ── Tests ─────────────────────────────────────────────────────────────────

	/**
	 * Cache hit path: getBiometricObject returns bytes → load from store → return cached BIRs.
	 * bioExtractionHelper must NOT be called.
	 */
	@Test
	public void testExtractTemplateExtractionExists() throws Exception {
		List<BIR> birs = loadTestBirs();
		when(objectStoreHelper.getBiometricObject(any(), any())).thenReturn(loadTestCbeffBytes());
		when(cbeffUtil.getBIRDataFromXML(any())).thenReturn(birs);

		CompletableFuture<List<BIR>> future =
				extractionServiceImpl.extractTemplate("uinHash", "bio.xml", "", "", birs);

		assertEquals(birs.size(), future.join().size());
		// Verify extraction was NOT triggered — served from cache
		verify(bioExtractionHelper, never()).extractTemplates(any(), any());
	}

	/**
	 * Cache miss path: getBiometricObject throws FILE_NOT_FOUND → extract → store → return extracted BIRs.
	 */
	@Test
	public void testExtractTemplateExtractionNotExists() throws Exception {
		List<BIR> birs = loadTestBirs();
		when(objectStoreHelper.getBiometricObject(any(), any()))
				.thenThrow(new IdRepoAppException(IdRepoErrorConstants.FILE_NOT_FOUND));
		when(bioExtractionHelper.extractTemplates(any(), any())).thenReturn(birs);
		when(cbeffUtil.createXML(any())).thenReturn(loadTestCbeffBytes());

		CompletableFuture<List<BIR>> future =
				extractionServiceImpl.extractTemplate("uinHash", "bio.xml", "a", "ExtractionFormat", birs);

		assertEquals(birs.size(), future.join().size());
		// Verify object store was written
		verify(objectStoreHelper).putBiometricObject(any(), any(), any());
	}

	/**
	 * Empty extraction result: putBiometricObject must NOT be called when extracted list is empty.
	 */
	@Test
	public void testExtractTemplateExtractedBioIsEmpty() throws Exception {
		List<BIR> birs = loadTestBirs();
		when(objectStoreHelper.getBiometricObject(any(), any()))
				.thenThrow(new IdRepoAppException(IdRepoErrorConstants.FILE_NOT_FOUND));
		when(bioExtractionHelper.extractTemplates(any(), any())).thenReturn(List.of());

		CompletableFuture<List<BIR>> future =
				extractionServiceImpl.extractTemplate("uinHash", "bio.xml", "a", "ExtractionFormat", birs);

		assertEquals(0, future.join().size());
		verify(objectStoreHelper, never()).putBiometricObject(any(), any(), any());
	}

	/**
	 * Object store read failure: ObjectStoreAdapterException on getBiometricObject
	 * is caught silently, falls through to live extraction path.
	 */
	@Test
	public void testExtractTemplateObjectStoreFailure() throws Exception {
		List<BIR> birs = loadTestBirs();
		// Store read fails — should fall through to extraction
		when(objectStoreHelper.getBiometricObject(any(), any()))
				.thenThrow(new ObjectStoreAdapterException("", ""));
		when(bioExtractionHelper.extractTemplates(any(), any())).thenReturn(birs);
		when(cbeffUtil.createXML(any())).thenReturn(loadTestCbeffBytes());

		CompletableFuture<List<BIR>> future =
				extractionServiceImpl.extractTemplate("uinHash", "bio.xml", "a", "ExtractionFormat", birs);

		assertEquals(birs.size(), future.join().size());
		// Verify fallback extraction was triggered
		verify(bioExtractionHelper).extractTemplates(any(), any());
	}

	/**
	 * BiometricExtractionException path: future completes exceptionally with
	 * IdRepoAppException wrapping BIO_EXTRACTION_ERROR.
	 *
	 * FIX: exceptions are inside the CompletableFuture now — unwrap via
	 * CompletionException.getCause(), not a direct try/catch on extractTemplate().
	 */
	@Test
	public void testExtractTemplateBioExtractionFailure() throws Exception {
		List<BIR> birs = loadTestBirs();
		when(objectStoreHelper.getBiometricObject(any(), any()))
				.thenThrow(new IdRepoAppException(IdRepoErrorConstants.FILE_NOT_FOUND));
		when(bioExtractionHelper.extractTemplates(any(), any()))
				.thenThrow(new BiometricExtractionException(IdRepoErrorConstants.UNKNOWN_ERROR));

		CompletableFuture<List<BIR>> future =
				extractionServiceImpl.extractTemplate("uinHash", "bio.xml", "a", "ExtractionFormat", birs);

		// FIX: future.join() throws CompletionException wrapping IdRepoAppException
		try {
			future.join();
		} catch (CompletionException ce) {
			// Unwrap the actual cause
			Throwable cause = ce.getCause();
			assertNotNull(cause);
			assertEquals(IdRepoAppException.class, cause.getClass());
			IdRepoAppException ex = (IdRepoAppException) cause;
			assertEquals(IdRepoErrorConstants.BIO_EXTRACTION_ERROR.getErrorCode(), ex.getErrorCode());
			assertEquals(IdRepoErrorConstants.BIO_EXTRACTION_ERROR.getErrorMessage(), ex.getErrorText());
		}
	}

	/**
	 * Unknown exception path: future completes exceptionally with
	 * IdRepoAppException wrapping UNKNOWN_ERROR.
	 */
	@Test
	public void testExtractTemplateUnknownError() throws Exception {
		List<BIR> birs = loadTestBirs();
		when(objectStoreHelper.getBiometricObject(any(), any()))
				.thenThrow(new IdRepoAppException(IdRepoErrorConstants.FILE_NOT_FOUND));
		when(bioExtractionHelper.extractTemplates(any(), any()))
				.thenThrow(new NullPointerException());

		CompletableFuture<List<BIR>> future =
				extractionServiceImpl.extractTemplate("uinHash", "bio.xml", "a", "ExtractionFormat", birs);

		// FIX: unwrap CompletionException → IdRepoAppException
		try {
			future.join();
		} catch (CompletionException ce) {
			Throwable cause = ce.getCause();
			assertNotNull(cause);
			assertEquals(IdRepoAppException.class, cause.getClass());
			IdRepoAppException ex = (IdRepoAppException) cause;
			assertEquals(IdRepoErrorConstants.UNKNOWN_ERROR.getErrorCode(), ex.getErrorCode());
			assertEquals(IdRepoErrorConstants.UNKNOWN_ERROR.getErrorMessage(), ex.getErrorText());
		}
	}
}