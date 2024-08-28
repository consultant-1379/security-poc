/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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
import java.security.cert.X509Certificate;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementImportExtCAHandlerTest {

    @InjectMocks
    CertificateManagementImportExtCAHandler certificateManagementImportExtCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    ExtCACertificateManagementService extCaCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportExtCAHandler.class);

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

        MockitoAnnotations.initMocks(this);

        properties.put("command", "EXTERNALCACERTIMPORT");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.EXTERNALCACERTIMPORT);

        final URL url = Thread.currentThread().getContextClassLoader().getResource("MyRoot.crt");
        String filename = url.getFile();
        filename = URLDecoder.decode(filename);
        x509Certificate = BaseTest.getCertificate(filename);

        certificate.setX509Certificate(x509Certificate);
        Mockito.when(eServiceRefProxy.getExtCaCertificateManagementService()).thenReturn(extCaCertificateManagementService);

        Mockito.when(commandHandlerUtils.getCertificateFromInputFile(command)).thenReturn(x509Certificate);
    }

    @Test
    public void testProcessCommandImportExtCA() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);
        command.setProperties(properties);
        Mockito.doNothing().when(extCaCertificateManagementService).importCertificate("caName", certificate.getX509Certificate(), false);

        final PkiCommandResponse pkiCommandResponse = certificateManagementImportExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);

    }

    @Test
    public void testProcessCommandForceImportExtCA() {
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", false);

        command.setProperties(properties);
        Mockito.doNothing().when(extCaCertificateManagementService).forceImportCertificate("caName", certificate.getX509Certificate(), false);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandImportExtCAException1() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", false);

        command.setProperties(properties);
        Mockito.doThrow(new CertificateAlreadyExistsException("Error")).when(extCaCertificateManagementService).forceImportCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCAException2() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new ExternalCAAlreadyExistsException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_MissingMandatoryFieldException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new MissingMandatoryFieldException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateFieldException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new CertificateFieldException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_ExternalCredentialMgmtServiceException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new ExternalCredentialMgmtServiceException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateNotFoundException() {
        properties.put("pathFile", "myFile");
        command.setProperties(properties);

        Mockito.doThrow(new CertificateNotFoundException("Error")).when(commandHandlerUtils).getCertificateFromInputFile(command);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_CertificateException() {
        properties.put("pathFile", "myFile");
        command.setProperties(properties);

        Mockito.doThrow(new CertificateException("Error")).when(commandHandlerUtils).getCertificateFromInputFile(command);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_ExpiredCertificateException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new ExpiredCertificateException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_IllegalArgumentException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", "NONE");

        command.setProperties(properties);

        Mockito.doThrow(IllegalArgumentException.class).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class), Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_Exception() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);

        Mockito.doThrow(Exception.class).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class), Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCA_SecurityViolationException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);
        command.setProperties(properties);
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(extCaCertificateManagementService).importCertificate("caName",
                certificate.getX509Certificate(), false);

        certificateManagementImportExtCaHandler.process(command);

    }

    @Test
    public void testProcessCommandForceImportExtCA_SecurityViolationException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", false);

        command.setProperties(properties);
        Mockito.doNothing().when(extCaCertificateManagementService).forceImportCertificate("caName", certificate.getX509Certificate(), false);

        certificateManagementImportExtCaHandler.process(command);

    }

    @Test
    public void testProcessCommandImportExtCAIssuerCertificateNotFoundException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new CertificateNotFoundException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCAExternalCANotFoundException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", true);

        command.setProperties(properties);
        Mockito.doThrow(new ExternalCANotFoundException("Error")).when(extCaCertificateManagementService).importCertificate(Matchers.eq("caName"), Mockito.any(X509Certificate.class),
                Matchers.eq(false));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCANoCnInSubjectDn() throws java.security.cert.CertificateException, IOException  {
        properties.put("name", "");
        properties.put("pathFile", "myFile");
        properties.put("chainrequired", false);

        command.setProperties(properties);
        X509Certificate x509CertificateNoCn;
        final URL url = Thread.currentThread().getContextClassLoader().getResource("NO_CN.crt");
        String filename = url.getFile();
        x509CertificateNoCn = BaseTest.getCertificate(filename);
        Mockito.when(eServiceRefProxy.getExtCaCertificateManagementService()).thenReturn(extCaCertificateManagementService);
        Mockito.when(commandHandlerUtils.getCertificateFromInputFile(command)).thenReturn(x509CertificateNoCn);
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementImportExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }
}
