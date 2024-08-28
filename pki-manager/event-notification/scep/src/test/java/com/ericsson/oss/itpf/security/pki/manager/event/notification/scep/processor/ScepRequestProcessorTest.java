/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.processor;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.util.Pkcs10RequestParser;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.digitalsignature.xml.DigitalSignatureValidator;
import com.ericsson.oss.itpf.security.pki.common.util.exception.OTPNotFoundInCSRException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.XMLException;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.DigitalSignatureValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExistsException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl.CredentialsManager;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.common.builders.ScepResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.scep.dispatcher.SignedScepResponseMessageDispatcher;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.EntityManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepRequestMessage;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

@RunWith(MockitoJUnitRunner.class)
/**
 * Test class for ScepRequestProcessorTest
 * 
 */
public class ScepRequestProcessorTest {
    @InjectMocks
    private ScepRequestProcessor scepRequestProcessor;
    @Mock
    private static EntityManagementService entityManagementService;
    @Mock
    private EntityCertificateManagementService entityCertificateManagementService;
    @Mock
    private ScepResponseBuilder scepResponseBuilder;
    @Mock
    private static Pkcs10RequestParser pkcs10RequestParser;
    @Mock
    private Logger logger;
    @Mock
    private SignedScepResponseMessageDispatcher scepResponseMessageDispatcher;
    @Mock
    private CertificateRequest requestCsr;
    @Mock
    CredentialsManager credentialManager;
    @Mock
    private Certificate certificate;

    @Mock
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private DigitalSignatureValidator xMLDigitalSignatureValidator;

    @Mock
    private CertificateManagementLocalService certificateManagementLocalService;

    @Mock
    private EntityManagementLocalService entityManagementLocalService;

    private static SignedScepRequestMessage scepRequestMessage;

    private static X500Name subjectName;

    private static String entityName = "ERBS_1";

    private static String otp = "Hdar32";

    private Set<X509Certificate> trustCertificateSet = new HashSet<X509Certificate>();

    static String scepRequestString = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+PHNjZXBSZXF1ZXN0Pjxjc3I+TUlJQ3d6Q0NBYXNDQVFBd1pqRUxNQWtHQTFVRUJoTUNTVTR4RWpBUUJnTlZCQWdNQ1ZSbGJHRnVaMkZ1WVRFVE1CRUdBMVVFQnd3S1NIbGtaWEppWVdKaFpERU1NQW9HQTFVRUNnd0RWRU5UTVJFd0R3WURWUVFMREFoRlVrbERVMU5QVGpFTk1Bc0dBMVVFQXd3RVVrRnFZVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFONnE1UkFUUDZOSGhKMzVKL3pYM3RHQjdVbUkxeVRRb2VYMGo5TUs3RWpTMGRqMkNveGI5ZHBrVlNxVHZFOEFmSndtaFIzVTR2c1ZjSytGNjExYTcrZTdCdUJUSi9lRDF5Sk1aQ2NwaXl1cUZoQ0JlaHJYTGFtSXN2TkFLTnhHenZScXc2Ritxb2NPZzVsRmhyMjZwMlIvVW1PWVJaOGkyMG9KU29xUXFXYXRFVUVWZmk5alJsaFBxNm1pYUNSYUZzd2ZaNm1Bcjd4eHRWeGxvUDVlU1FLWkZsaEdpNURMTHRFcUJlUlBXaXpIL1N6QlNLUGFkWklNV2U1ZXN1a2lYYXV6VEc1bFBKWWtRakZEN3BjY2o4U3R6UytzWlBtdTMzYndxVExJSWd0UkxIeUhPWGd4VDNvMmhNSEtDa1Q4WWdzVWU4Z00xclJxdTBiV3RzRkRrckVDQXdFQUFhQVlNQllHQ1NxR1NJYjNEUUVKQnpFSkRBZDBaWE4wTVRJek1BMEdDU3FHU0liM0RRRUJCUVVBQTRJQkFRRFZlcXRWUEppM2pBT1hhZGpNOVlGVVVMY3FCSzg4M21Yb0loOGRBaDU2U1RWVXBvMWErREtmT1FVRGhIUWsrL01OVE9nd3lVSFl2U2djQ1NaTW1XSHhjL0h5eDh0WjhmcWdUMkhBdHZoWHlPZ2YyWmQrcUFiM2tLdm5uR3VSRjZDQm9UajhxTUU4Qm1kZDE5KzZ6aTVFb1BnRFFJbkdxT1E0ekpwcHM0TzZCQmJwbzJ2YVIxYkIyVFJINy81MmROKytQWTMrS3JDbHQyamtxcnBJbkhIME1HTm9OK2ZJcy9vdmYyU2NKRDNQWGVxVWZwbXhuSkp1elBraEZhRFpNNEozR2VFZExOdEluN3UxMWFiZW5URHhOY0Q4dHRVSWRMMlQ3VkFDM0VXUlFNWU1nUk5zOVdWaisyc0pxTXNVMmgxNUI2UVo1TnlPU21KOUpxSk9CUTR0PC9jc3I+PHRyYW5zYWN0aW9uSWQ+MTI0MzUzNHNkZmdkZnNxMzQ8L3RyYW5zYWN0aW9uSWQ+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8yMDAxL1JFQy14bWwtYzE0bi0yMDAxMDMxNSIvPjxTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGRzaWctbW9yZSNyc2Etc2hhMjU2Ii8+PFJlZmVyZW5jZSBVUkk9IiI+PFRyYW5zZm9ybXM+PFRyYW5zZm9ybSBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyNlbnZlbG9wZWQtc2lnbmF0dXJlIi8+PC9UcmFuc2Zvcm1zPjxEaWdlc3RNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxLzA0L3htbGVuYyNzaGEyNTYiLz48RGlnZXN0VmFsdWU+THc1WjdoNmFQa1VtOUxjcjcyWUgybUFtQnQ2RjhwSUFJQkZYTWJmakxCOD08L0RpZ2VzdFZhbHVlPjwvUmVmZXJlbmNlPjwvU2lnbmVkSW5mbz48U2lnbmF0dXJlVmFsdWU+YXo3NEF4bGpuUWZpR04vaUdaOVFXTkRUcVZXL3pRdlplUEp2bjZhbkV3QjRDTDFsYmMvbUlmelV5R25RVmtRY2NuaDdoU1VnMHc2YQ0KdFFRY2ZrUUFKY3loQSt5cDdxZ2M3VGlNbXNUczBZMlk4MHh4aFV1TElmRE0wZmptU0txdHYvM3RQekp2LytkWklZcDFsOVhOaVEwUA0KcCt0a0FiR1dhaG1yUzJ2MEFxNy9oMU0xbXVGOTdVaUIvWStxOWwyS2tCUGhqVXZ0ZDZkMVRRM0JXc2JtZld4OEl5c1pYdkt5aytURw0Kc2l0b0prSW05U0xyS0xSN3BsbVpCVkd3K004NFpBa2crdFJQdFJpSUJkS2VNcXU0UXZrcWJPdVJwMFB3djVlNDc4NmI0S0o5WXIvTQ0KOUQ0dnBRTGVDQ2JUMEhvaUFLZnRtc0JBNWphRDFxK2VRbVJiZEE9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRCtUQ0NBdUdnQXdJQkFnSUVKRzIxRURBTkJna3Foa2lHOXcwQkFRVUZBREF4TVJFd0R3WURWUVFLREFoRmNtbGpjM052YmpFYw0KTUJvR0ExVUVBd3dUVEZSRlNWQlRaV05PUldOMWMxSnZiM1JEUVRBZUZ3MHhOREV4TURVd05qSTVNamRhRncweE9URXhNRE14TWpJNQ0KTWpGYU1DNHhMREFxQmdOVkJBTU1JMHhVUlVsUVUyVmpUa1ZqZFhOaGRHTnNkbTB4TURJMFUyTmxjRkpoVTJWeWRtVnlNSUlCSWpBTg0KQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcHV1QUdabXZzVjladmxYeW15QzZPVC9nL3h5L25MVURPTE5nOCs1YQ0KUHo2VlMvR3lIT2FsYlcraHJ4d1JRZjJSU0ROUHJoWjFMcXZtaHQxSk9HVnlBRUdHQTRyS1c4NXdhQXFsKzZrRThJNlhGNS9YYnhLOQ0KeDN0NzFienBXVkZVb0JNYTZDMUE0TGJPREw2bnBMNjhSaXVRQityOEsyZXAzSFdTNm42ZWVXNlEyWXVVNG1LL0RRaXhVc3RqdG1wSQ0KWkdRbWVqZkdIb0hrS2E5dkRqeEpYeXp0RTlkUHZSZUZMVFV2TXFvckpwc0RHVzNPREUvRWFNY0FrRjBneVIvcmRFUFNUWUtEd1NwRw0KV3dtOXgxVzFSRE5KZ2tjdjh3ejZDWHhhd2lIb2FpWmJBVUdnTWdtT2VOWEZMNTZUMG56c3ZiNm82WTlMNHo5ZDB2Z2NKUk9vMHdJRA0KQVFBQm80SUJHakNDQVJZd0hRWURWUjBPQkJZRUZQaVNMLzNlWTk1clBhQUk2T1lvTVk5QXRGYWVNQXdHQTFVZEV3RUIvd1FDTUFBdw0KSHdZRFZSMGpCQmd3Rm9BVWt1ZU9KUEl3M1M4L2RZZmllV2NzaEVXS0R6Z3dnYlVHQTFVZEh3U0JyVENCcWpCVG9GR2dUNFpOYUhSMA0KY0RvdkwyTmtjREV1WTJSd2N5NWhkR2gwWlcwdVpXVnBMbVZ5YVdOemMyOXVMbk5sT2pJek56Y3ZhVzUwWlhKdVlXd3ZURlJGU1ZCVA0KWldOT1JXTjFjMUp2YjNSRFFTNWpjbXd3VTZCUm9FK0dUV2gwZEhBNkx5OWpaSEF5TG1Oa2NITXVZWFJvZEdWdExtVmxhUzVsY21sag0KYzNOdmJpNXpaVG95TXpjM0wybHVkR1Z5Ym1Gc0wweFVSVWxRVTJWalRrVmpkWE5TYjI5MFEwRXVZM0pzTUE0R0ExVWREd0VCL3dRRQ0KQXdJRHFEQU5CZ2txaGtpRzl3MEJBUVVGQUFPQ0FRRUFPNDBjNUJUSlpMOWZRWHFnYmpXR2ZOOUtha1YrVCtXamFvY3JVRzZjSzA0Wg0KSHRqM3gxY2t0ZEkvNzdMbXNJOXhwdU9LUWZWbU1lMEpnaFk5cUJsU28wVzJNNkxVeXBzRGFwQUFZU0ZmaDg4ZHR3R09Ha2xrU29HSw0KREJPRDNkcXVNMDIvdnFqZmZhN0MzWXUvekJINTJwekcraDhTeUVSZ21Wb3RLNnBPbC95UjZxeEYycUJ4dWsraTNoU3NqQlV1QTFSSw0KY2VoUVFudTFBZzBSY3BHem5BSDRCbzgycFg4WW1QdzRYWHdWaXNwdDdMbkw2ZlYzSjkydEdENEl6UnNuOUpFQ1hFakZHbUZSa3NiQg0KOEV3RWNxRVhKSUNIT2MyY1AxUktOVndwUVpDdExaVWNMRjlNWE5DRUpPajRQbHA2L0lINHZhdHhkVllwTUdvK0JGNkJnUT09PC9YNTA5Q2VydGlmaWNhdGU+PC9YNTA5RGF0YT48L0tleUluZm8+PC9TaWduYXR1cmU+PC9zY2VwUmVxdWVzdD4=";

    byte[] requestArray = null;

    private final String keyStoreType = "PKCS12";
    private final String filePath = "/LTEIPSecNEcus_Sceprakeystore_1.p12";
    private final String password = "C4bCzXyT";
    private final String keyStoreAlias = "lteipsecnecus";

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws KeyStoreException
     * @throws UnrecoverableKeyException
     */
    @Before
    public void setUp() throws KeyStoreException, UnrecoverableKeyException {
        scepRequestMessage = new SignedScepRequestMessage();
        requestArray = scepRequestString.getBytes();
        if (StringUtility.isBase64(new String(requestArray))) {
            requestArray = Base64.decode(requestArray);
        }
        scepRequestMessage.setScepRequest(requestArray);
        mockTrustCertAndCsrAttributes();
    }

    /**
     * Method to test processing of scepRequestMessage.
     * 
     * @throws IOException
     */
    @Test
    public void testProcessRequest() throws IOException {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenReturn(true);

        Mockito.when(certificateManagementLocalService.generateCertificate(Mockito.anyString(), (CertificateRequest) Mockito.any())).thenReturn(certificate);
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test ProcessRequest DigitalSigningFailedException.
     */
    @Test
    public void testProcessRequest_DigitalSigningFailedException() {
        Mockito.when(entityManagementService.isOTPValid(entityName, otp)).thenReturn(true);
        Mockito.when(entityCertificateManagementService.generateCertificate(Mockito.anyString(), (CertificateRequest) Mockito.any())).thenReturn(certificate);
        Mockito.doThrow(new DigitalSigningFailedException("digital signing falied")).when(scepResponseMessageDispatcher).sendResponseMessage((SignedScepResponseMessage) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test CertificateExistsScenario.
     * 
     * @throws CertificateExistsException
     */
    @Test
    public void testCertificateExistsScenario() {
        Mockito.when(entityManagementService.isOTPValid(entityName, otp)).thenReturn(true);
        // Mockito.when(entityCertificateManagementService.generateCertificate(Mockito.anyString(), (CertificateRequest) Mockito.any())).thenThrow(new
        // CertificateExistsException("CertificateAlreadyExists"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test EntityNotFoundScenario
     * 
     * @throws EntityNotFoundException
     */
    @Test
    public void testEntityNotFoundScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new EntityNotFoundException("EntityNotFound"));
        Mockito.doNothing().when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test InvalidEntityScenario
     * 
     * @throws InvalidEntityException
     */
    @Test
    public void testInvalidEntityScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new InvalidEntityException("Invalid EntityException"));
        Mockito.doNothing().when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test InvalidCsrScenario
     * 
     * @throws InvalidCSRException
     */
    @Test
    public void testInvalidCsrScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new InvalidCertificateRequestException("Invalid CSr"));
        Mockito.doNothing().when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test CertificateGenerationException
     * 
     * @throws CertificateGenerationException
     */
    @Test
    public void testCertificateGenerationException() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new CertificateGenerationException("Certificate Generation Exception"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test EntityException
     * 
     * @throws EntityServiceException
     */
    @Test
    public void testEntityException() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new EntityServiceException());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test CertificateServiceException
     * 
     * @throws CertificateServiceException
     */
    @Test
    public void testCertificateServiceExceptionScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new CertificateServiceException("Certificate service exception"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test AlgorithmNotFoundException
     * 
     * @throws AlgorithmNotFoundException
     */
    @Test
    public void testAlgorithmNotFoundExceptionScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new AlgorithmNotFoundException("Algorithm not found"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test InvalidCAException
     * 
     * @throws InvalidCAException
     */
    @Test
    public void testInvalidCAExceptionScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new InvalidCAException("Invalid CA"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test EntityNotFoundScenario
     * 
     * @throws OTPExpiredException
     */
    @Test
    public void testOTPExpiredExceptionScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new OTPExpiredException("OTP expired"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test OTPNotFoundInCSRException
     * 
     * @throws OTPNotFoundInCSRException
     */
    @Test
    public void testOTPNotFoundInCSRExceptionScenario() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new OTPNotFoundInCSRException("OTP not found"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test DigitalSignatureValidationException
     */
    @Test
    public void testDigitalSignatureValidationException() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new DigitalSignatureValidationException("Failed to validate digital signature"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test CredentialsManagementServiceException
     */
    @Test
    public void testCredentialsManagementServiceException() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new CredentialsManagementServiceException("Failed to get trust certificates"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test RevokedCertificateException
     */
    @Test
    public void testRevokedCertificateException() {
        Mockito.when(certificatePersistenceHelper.getCertificate((X509Certificate) Mockito.any())).thenThrow(new RevokedCertificateException("Certificate Chain validation failed"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test CertificateServiceException
     */
    @Test
    public void testCertificateServiceException() {
        Mockito.when(certificatePersistenceHelper.getCertificate((X509Certificate) Mockito.any())).thenThrow(new CertificateServiceException());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test CertificateNotFoundException
     */
    @Test
    public void testCertificateNotFoundException() {
        Mockito.when(certificatePersistenceHelper.getCertificate((X509Certificate) Mockito.any())).thenThrow(new CertificateNotFoundException("The received scep signer certificate is not found"));
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * test method testValidateDigitalSignature_EntityNotFound
     */
    @Test
    public void testValidateDigitalSignature_EntityNotFound() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new EntityNotFoundException("EntityNotFound"));
        Mockito.doNothing().when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        Mockito.doThrow(new CertificateNotFoundException()).when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * test method testValidateDigitalSignature_RevokedCertificateException
     */
    @Test
    public void testValidateDigitalSignature_RevokedCertificateException() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new EntityNotFoundException("EntityNotFound"));
        Mockito.doNothing().when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        Mockito.doThrow(new RevokedCertificateException("Certificate Chain validation failed")).when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * test method testValidateDigitalSignature_CertificateServiceException
     */
    @Test
    public void testValidateDigitalSignature_CertificateServiceException() {
        Mockito.when(entityManagementLocalService.isOTPValid(entityName, otp)).thenThrow(new EntityNotFoundException("EntityNotFound"));
        Mockito.doNothing().when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        Mockito.doThrow(new CertificateServiceException()).when(certificateManagementLocalService).validateCertificateChain((X509Certificate) Mockito.any());
        scepRequestProcessor.processRequest(scepRequestMessage);
    }

    /**
     * Method to test XMLException
     * 
     * @throws XMLException
     */
    @Test
    public void testXMLExceptionScenario() {
        final SignedScepRequestMessage scepRequest = new SignedScepRequestMessage();
        scepRequest.setScepRequest(new byte[1]);
        scepRequestProcessor.processRequest(scepRequest);
        Mockito.verify(logger).error("Error while getting document from request message.");
    }

    private void mockTrustCertAndCsrAttributes() throws KeyStoreException {
        setTrustCertificateSet();
        subjectName = new X500Name("CN=" + "ERBS_1");
        Mockito.when(credentialManager.getTrustCertificateSet()).thenReturn(trustCertificateSet);
        Mockito.when(pkcs10RequestParser.getRequestDN(Mockito.any(PKCS10CertificationRequest.class))).thenReturn(subjectName);
        Mockito.when(pkcs10RequestParser.getPassword(Mockito.any(PKCS10CertificationRequest.class))).thenReturn(otp);
        Mockito.when(entityManagementService.isOTPValid(entityName, otp)).thenReturn(true);
    }

    private void setTrustCertificateSet() {
        java.security.cert.Certificate cert = null;
        try {
            final KeyStore keyStore = KeyStore.getInstance(keyStoreType);
            keyStore.load(ScepRequestProcessorTest.class.getResourceAsStream(filePath), password.toCharArray());
            cert = keyStore.getCertificate(keyStoreAlias);
            trustCertificateSet.add((X509Certificate) cert);
        } catch (final KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }
    }
}
