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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.URL;
import java.net.URLDecoder;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.ReIssueType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagemtUpdateCAHandlerTest {
    @InjectMocks
    CertificateManagemtUpdateCAHandler certificateManagemtUpdateCaHandler;

    @Mock
    CliUtil cliUtil;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagemtUpdateCAHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();
    Certificate certificate = new Certificate();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);

        properties.put("command", "CACERTIFICATEMANAGEMENTREISSUE");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CACERTIFICATEMANAGEMENTREISSUE);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        x509Certificate = BaseTest.getCertificate(filename);
        certificate.setX509Certificate(x509Certificate);

        Mockito.doNothing().when(exportedItemsHolder).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);

    }

    @Test
    public void testProcessCommandEntityNameNull() {
        properties.put("entityname", "");
        command.setProperties(properties);

        Mockito.when(caCertificateManagementService.generateCertificate(" ")).thenReturn(null);

        certificateManagemtUpdateCaHandler.process(command);

        Mockito.verify(cliUtil).prepareErrorMessage(ErrorType.UNSUPPORTED_COMMAND_ARGUMENT_ERROR.toInt(), PkiErrorCodes.ENTITY_NAME_CANNOT_BE_NULL_OR_EMPTY, null);
    }

    @Test
    public void testProcess_Renew() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("reissuetype", "renew");
        properties.put("level", "CA");
        properties.put("revoke", "REVOKE");
        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Certificate(s) for CA Entity ENMROOTCA renewed and revoked successfully");

    }

    @Test
    public void testProcess_RenewWithoutRevoke() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("reissuetype", "renew");
        properties.put("level", "CA");

        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Certificate(s) for CA Entity ENMROOTCA renewed successfully");

    }

    @Test
    public void testProcess_Rekey() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("reissuetype", "rekey");
        properties.put("level", "CA");
        properties.put("revoke", "REVOKE");
        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Certificate(s) for CA Entity ENMROOTCA rekeyed and revoked successfully");

    }

    @Test
    public void testProcess_RekeyWithoutRevoke() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("reissuetype", "rekey");
        properties.put("level", "CA");

        command.setProperties(properties);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertEquals(pkiCommandResponse.getMessage(), "Certificate(s) for CA Entity ENMROOTCA rekeyed successfully");

    }

    @Test
    public void testProcessAlgorithmNotFoundException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new AlgorithmNotFoundException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ALGORITHM_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.ALGORITHM_NOT_FOUND_EXCEPTION)));
    }

    @Test
    public void testProcessCANotFoundException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new CANotFoundException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CA_NOT_FOUND_EXCEPTION.toInt(), PkiErrorCodes.CA_NOT_FOUND_EXCEPTION)));
    }

    @Test
    public void testProcessCertificateGenerationException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new CertificateGenerationException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.EXCEPTION_IN_CERTIFICATE_GENERATION.toInt(), PkiErrorCodes.EXCEPTION_IN_CERTIFICATE_GENERATION)));
    }

    @Test
    public void testProcessCertificateServiceException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new CertificateServiceException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessInvalidCAException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new InvalidCAException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("CRL Generation Exception"));
    }

    @Test
    public void testProcessIssuerCertificateRevokedException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new IssuerCertificateRevokedException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ISSUER_CERTIFICATE_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.ISSUER_CERTIFICATE_REVOKED_EXCEPTION_CA)));
    }

    @Test
    @Ignore
    public void testProcessKeyPairGenerationException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new KeyPairGenerationException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.KEYPAIR_GENERATION_EXCEPTION.toInt(), PkiErrorCodes.EXCEPTION_IN_KEYPAIR_GENERATION)));
    }

    @Test
    public void testProcessRevokedCertificateException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);


        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(
                new RevokedCertificateException(CliUtil.buildMessage(ErrorType.CERTIFICATE_ALREADY_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION)));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.CERTIFICATE_ALREADY_REVOKED_EXCEPTION.toInt(), PkiErrorCodes.CERTIFICATE_ALREADY_REVOKED_EXCEPTION)));
    }

    @Test
    public void testProcessRevocationServiceException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new RevocationServiceException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Suggested Solution :  retry "));
    }

    @Test
    public void testProcessRootCertificateRevocationException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new RootCertificateRevocationException("CRL Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(CliUtil.buildMessage(ErrorType.ROOT_CA_CANNOT_REVOKED_CERTIFICATE.toInt(), Constants.EMPTY_STRING)));
    }

    @Test
    public void testProcessExpiredCertificateException() throws IOException {
        MockitoAnnotations.initMocks(certificateManagemtUpdateCaHandler);
        properties.put("caname", "Erbs123");
        properties.put("serialNo", "lgyus");

        command.setProperties(properties);

        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new ExpiredCertificateException("Certificate Generation Exception"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagemtUpdateCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11603 "));
    }

    @Test
    public void testProcess_Rekey_SecurityViolationExeption() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("reissuetype", "rekey");
        properties.put("level", "CA");
        properties.put("revoke", "REVOKE");
        command.setProperties(properties);
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(caCertificateManagementService).rekeyCertificate("caName", ReIssueType.CA_WITH_ALL_CHILD_CAS);
        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

    }

    @Test
    public void testProcess_Renew_SecurityViolationException() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException {
        properties.put("entityname", "ENMROOTCA");
        properties.put("reissuetype", "renew");
        properties.put("level", "CA");
        properties.put("revoke", "REVOKE");
        command.setProperties(properties);
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(caCertificateManagementService).renewCertificate("caName", ReIssueType.CA_WITH_ALL_CHILD_CAS);
        Mockito.when(certificateManagemtUpdateCaHandler.process(command)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

    }

}
