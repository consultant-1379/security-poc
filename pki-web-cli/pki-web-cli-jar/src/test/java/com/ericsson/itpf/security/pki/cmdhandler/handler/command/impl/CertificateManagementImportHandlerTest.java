/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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

import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerCertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementImportHandlerTest {

    @InjectMocks
    CertificateManagementImportHandler certificateManagementImportHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();
    Certificate certificate = new Certificate();
    List<Certificate> certificates = new ArrayList<Certificate>();
    X509Certificate x509Certificate;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        properties.put("command", "CERTIFICATEMANAGEMENTIMPORT");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.CERTIFICATEMANAGEMENTIMPORT);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        final String filename = url.getFile();
        final String filePath = URLDecoder.decode(filename);
        final String osAppropriatePath = System.getProperty("os.name").contains("indow") ? filePath.substring(1) : filePath;
        properties.put("filePath", osAppropriatePath);
        x509Certificate = BaseTest.getCertificate(filePath);
        certificate.setX509Certificate(x509Certificate);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCertificateFromInputFile(command)).thenReturn(x509Certificate);
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);
    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementImportHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommandExtCA() throws Exception {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.RENEW_SUB_CAS);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommandForceExtCA() throws Exception {
        properties.put("force", "force");
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "RENEW_SUB_CAS");

        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).forceImportCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.RENEW_SUB_CAS);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommandExtCA_Reissue_Type_RENEW_SUB_CAS_WITH_REVOCATION() throws Exception {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "RENEW_SUB_CAS_WITH_REVOCATION");
        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.RENEW_SUB_CAS_WITH_REVOCATION);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommandExtCA_Reissue_Type_REKEY_SUB_CAS() throws Exception {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "REKEY_SUB_CAS");
        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.REKEY_SUB_CAS);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommandExtCA_Reissue_Type_REKEY_SUB_CAS_WITH_REVOCATION() throws Exception {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "REKEY_SUB_CAS_WITH_REVOCATION");
        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.REKEY_SUB_CAS_WITH_REVOCATION);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommandExtCA_Reissue_Type_NONE() throws Exception {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "NONE");
        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.NONE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommandExtCA_Rfc_Validation_False() throws Exception {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "false");
        properties.put("careissuetype", "NONE");
        command.setProperties(properties);

        Mockito.doNothing().when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), true, CAReIssueType.NONE);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate imported successfully."));

    }

    @Test
    public void testProcessCommand_AlgorithmNotFoundException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new AlgorithmNotFoundException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Provided Algorithm not found, Please check online help for the list of supported algorithms."));
    }

    @Test
    public void testProcessCommand_CertificateAlreadyExistsException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateAlreadyExistsException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11507 ErrorSuggested Solution : Please Use valid Certificate."));
    }

    @Test
    public void testProcessCommand_CANotFoundException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CANotFoundException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Given CA entity name is not found."));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateGenerationException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateGenerationException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Exception during Certificate parsing"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateNotFoundException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateNotFoundException("Error"));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateRevokedException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateRevokedException("Certificate already revoked."));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Certificate already revoked."));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateServiceException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateServiceException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_ExpiredCertificateException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new ExpiredCertificateException("Use valid Certificate for operation"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Use valid Certificate for operation"));
    }

    @Test
    public void testProcessCommandImportExtCA_IllegalArgumentException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new IllegalArgumentException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Import certificate failed. Certificate is invalid"));
    }

    @Test
    public void testProcessCommandImportExtCA_InvalidAuthorityKeyIdentifierExtension() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new InvalidAuthorityKeyIdentifierExtension("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_InvalidCAException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new InvalidCAException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Given Entity name is not active."));
    }

    @Test
    public void testProcessCommandImportExtCA_InvalidOperationException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new InvalidOperationException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Given Entity name is not Root CA."));
    }

    @Test
    public void testProcessCommandImportExtCA_IssuerCertificateRevokedException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new IssuerCertificateRevokedException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Issuer Certificate for the Entity is already revoked, Issuer Certificate must be valid to revoke Entity Certificate."));
    }

    @Test
    @Ignore
    public void testProcessCommandImportExtCA_IssuerNotFoundException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new IssuerNotFoundException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Issuer is not found, Please refer to an existing issuer."));
    }

    @Test
    public void testProcessCommandImportExtCA_MissingMandatoryFieldException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new MissingMandatoryFieldException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_UnSupportedCertificateVersion() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new UnSupportedCertificateVersion("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateFieldException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new CertificateFieldException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_RevocationServiceException() {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("pathFile", "myFile");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);
        Mockito.when(certificateManagementImportHandler.process(command)).thenThrow(new RevocationServiceException("Error"));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandExtCA_SecurityViolationException() throws SecurityViolationException, CertificateExtensionException, MissingMandatoryFieldException, UnSupportedCertificateVersion,
            AlgorithmNotFoundException, CANotFoundException, CertificateAlreadyExistsException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, IssuerCertificateRevokedException, IssuerNotFoundException, java.security.cert.CertificateRevokedException, InvalidOperationException {
        properties.put("caentityname", "caName");
        properties.put("rfcvalidation", "true");
        properties.put("careissuetype", "RENEW_SUB_CAS");
        command.setProperties(properties);

        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(caCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(),
                true, CAReIssueType.RENEW_SUB_CAS);

        certificateManagementImportHandler.process(command);

    }
}
