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

import java.net.URL;
import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.CommandHandlerUtils;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.itpf.security.pki.cmdhandler.util.ExportedItemsHolder;
import com.ericsson.itpf.security.pki.cmdhandler.util.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.itpf.security.pki.web.cli.local.service.api.PkiWebCliResourceLocalService;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.ExtCACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementExportExtCAHandlerTest {

    @InjectMocks
    CertificateManagementExportExtCAHandler certificateManagementExportExtCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    ExtCACertificateManagementService extCaCertificateManagementService;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Mock
    FileUtility fileUtil;

    @Mock
    CliUtil cliUtil;

    @Mock
    CertificateUtils certUtil;

    @Mock
    PkiWebCliResourceLocalService pkiWebCliResourceLocalService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportExtCAHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    X509Certificate x509Certificate;

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
        Mockito.doNothing().when((exportedItemsHolder)).save(Mockito.anyString(), Mockito.anyObject());
        Mockito.when(eServiceRefProxy.getExtCaCertificateManagementService()).thenReturn(extCaCertificateManagementService);
    }

    @Ignore
    @Test
    public void testProcessCommandExportExtCA() {

        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        final List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();
        x509Certificates.add(x509Certificate);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenReturn(x509Certificates);
        Mockito.when(fileUtil.getFileNameFromAbsolutePath(Mockito.anyString())).thenReturn("MyRoot.jks");
        final PkiCommandResponse pkiCommandResponse = certificateManagementExportExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    @Ignore
    @Test
    public void testProcessCommandExportExtCAWithNameWithBlanks() {
        properties.put(Constants.NAME, "caName 1");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        final List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();
        x509Certificates.add(x509Certificate);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName 1", null, false)).thenReturn(x509Certificates);

        final PkiCommandResponse pkiCommandResponse = certificateManagementExportExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.DOWNLOAD_REQ);
    }

    @Test
    public void testProcessCommandExportExtCAException1() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenThrow(ExternalCANotFoundException.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementExportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    public void testProcessCommandExportExtCAException2() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenThrow(CertificateNotFoundException.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementExportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    public void testProcessCommandExportExtCAException3() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenThrow(ExternalCredentialMgmtServiceException.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementExportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandExportExtCAException4() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenThrow(MissingMandatoryFieldException.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementExportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandExportExtCAException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenThrow(Exception.class);

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementExportExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessEntityExportCertHandler_SecurityViolationException() throws SecurityViolationException {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.SERIAL_NUMBER, null);
        command.setProperties(properties);
        final List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();
        x509Certificates.add(x509Certificate);
        Mockito.when(extCaCertificateManagementService.exportCertificate("caName", null, false)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));

        certificateManagementExportExtCaHandler.process(command);

    }
}
