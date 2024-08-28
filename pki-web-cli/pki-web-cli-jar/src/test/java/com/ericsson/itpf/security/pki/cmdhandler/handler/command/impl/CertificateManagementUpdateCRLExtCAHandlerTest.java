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

import static org.junit.Assert.*;

import java.io.*;
import java.security.cert.*;
import java.util.HashMap;
import java.util.Map;

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
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementUpdateCRLExtCAHandlerTest {
    @InjectMocks
    CertificateManagementUpdateCRLExtCAHandler certificateManagementUpdateCrlExtCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    ExtCACRLManagementService extCaCrlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    SystemRecorder systemRecorder;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportExtCAHandler.class);

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    X509CRL x509CRL;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "EXTERNALCACERTIMPORT");
        properties.put("name", "caName");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.EXTERNALCACERTIMPORT);
        x509CRL = getCRLFromInputFile("src/test/resources/testCA.crl");
        Mockito.when(eServiceRefProxy.getExtCaCrlManager()).thenReturn(extCaCrlManagementService);
    }

    /**
     * Test method for {@link com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.CertificateManagementListCAHandler#Process(com.ericsson.itpf.security.pki.cmdhandler.api.command)} .
     *
     * @throws CRLException
     * @throws IOException
     *
     * @throws EntityNotFoundException
     * @throws CertificateGenerationException
     */

    @Test
    public void testProcessCommandUpdateCRLExtCA() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doNothing().when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));
        final PkiCommandResponse pkiCommandResponse = certificateManagementUpdateCrlExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandUpdateCRLExtCA_1() {
        properties.put("name", "caName");
        properties.put("url", "d:/a/b/c");
        command.setProperties(properties);
        Mockito.doNothing().when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));

        final PkiCommandResponse pkiCommandResponse = certificateManagementUpdateCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandUpdateCRLExtCAWithWrongCRL() {
        properties.put("name", "caName");
        properties.put("pathFile", null);
        command.setProperties(properties);
        Mockito.doNothing().when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));

        final PkiCommandResponse pkiCommandResponse = certificateManagementUpdateCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandImportExtCAException_ExternalCANotFoundException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        command.setProperties(properties);
        Mockito.doThrow(new ExternalCANotFoundException("Error")).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCAException_MissingMandatoryFieldException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        command.setProperties(properties);
        Mockito.doThrow(new MissingMandatoryFieldException("Error")).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandImportExtCAException_ExternalCredentialMgmtServiceException() {
        properties.put("name", "caName");
        properties.put("pathFile", "myFile");
        command.setProperties(properties);
        Mockito.doThrow(new ExternalCredentialMgmtServiceException("Error")).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));

        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);

        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testProcessCommandUpdateCRLExtCAMissingMandatoryFieldException() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doThrow(MissingMandatoryFieldException.class).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));
        final PkiCommandResponse pkiCommandResponse = certificateManagementUpdateCrlExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandUpdateCRLExtCAExternalCRLException() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doThrow(ExternalCRLException.class).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Network problem: cannot download CRL file"));
    }

    @Test
    public void testProcessCommandUpdateCRLExtCAExternalCANotFoundException() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doThrow(ExternalCANotFoundException.class).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("11501 Invalid argument value:"));
    }

    @Test
    public void testProcessCommandUpdateCRLExtCAExternalCredentialMgmtServiceException() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doThrow(ExternalCredentialMgmtServiceException.class).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11099  Internal service error occurred Suggested Solution :  retry "));
    }

    @Test
    public void testProcessCommandUpdateCRLExtCAgenericException() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doThrow(Exception.class).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"), Matchers.any(ExternalCRLInfo.class));
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementUpdateCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("11099 Unexpected Internal Error"));
    }


    @Test
    public void testProcessCommandUpdateCRLExtCA_SecurityViolationException() throws CRLException, IOException {
        properties.put("filename", "testCA.crl");
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getCRLFromInputFile(Mockito.any(PkiPropertyCommand.class))).thenReturn(x509CRL);
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(extCaCrlManagementService).addExternalCRLInfo(Matchers.eq("caName"),
                Matchers.any(ExternalCRLInfo.class));
        certificateManagementUpdateCrlExtCaHandler.process(command);
    }


    private X509CRL getCRLFromInputFile(final String filePath) throws CRLException {
        InputStream crlFile = null;
        X509CRL x509CRL = null;
        if (filePath != null && !filePath.isEmpty()) {
            try {
                crlFile = new FileInputStream(filePath);
                if (crlFile != null) {
                    final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    x509CRL = (X509CRL) certificateFactory.generateCRL(crlFile);
                }
            } catch (FileNotFoundException | java.security.cert.CertificateException e) {
                e.printStackTrace();
                throw new CRLException();
            }
        }
        return x509CRL;
    }

}
