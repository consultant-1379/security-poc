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

import java.util.HashMap;
import java.util.Map;

import org.junit.*;
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
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementRemoveCRLExtCAHandlerTest {

    @InjectMocks
    CertificateManagementRemoveCRLExtCAHandler certificateManagementRemoveCrlExtCaHandler;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    ExtCACRLManagementService extCaCrlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementRemoveCRLExtCAHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "EXTERNALCAREMOVECRL");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.EXTERNALCAREMOVECRL);
        Mockito.when(eServiceRefProxy.getExtCaCrlManagementService()).thenReturn(extCaCrlManagementService);

    }

    @Test
    public void testCertificateManagementRemoveCRLExtCAHandler() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doNothing().when(extCaCrlManagementService).removeExtCRL("caName", "issuerName");

        final PkiCommandResponse pkiCommandResponse = certificateManagementRemoveCrlExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testRemoveCRLExtCAWithoutName() {
        properties.put(Constants.NAME, null);
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doNothing().when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error: 11332 Missing mandatory field:"));
    }

    @Test
    public void testRemoveCRLExtCAWithoutIssuerName() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, null);
        command.setProperties(properties);
        Mockito.doNothing().when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testRemoveCRLWithExternalCANotFoundException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doThrow(ExternalCANotFoundException.class).when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    @Ignore
    public void testRemoveCRLWithExternalCAInUseException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doThrow(ExternalCAInUseException.class).when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains(PkiErrorCodes.INVALID_ARGUMENT));
    }

    @Test
    public void testRemoveCRLWithExternalCACRLsExistException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doThrow(ExternalCACRLsExistException.class).when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testRemoveCRLWithExternalCredentialMgmtServiceException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doThrow(ExternalCredentialMgmtServiceException.class).when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testRemoveCRLWithExternalCRLNotFoundException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doThrow(ExternalCRLNotFoundException.class).when(extCaCrlManagementService).removeExtCRL(Mockito.anyString(), Mockito.anyString());
        final PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) certificateManagementRemoveCrlExtCaHandler.process(command);
        assertTrue(pkiCommandResponse.getMessage().contains("Error"));
    }

    @Test
    public void testCertificateManagement_SecurityViolationException() {
        properties.put(Constants.NAME, "caName");
        properties.put(Constants.ISSUER_NAME, "issuerName");
        command.setProperties(properties);
        Mockito.doThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION)).when(extCaCrlManagementService).removeExtCRL("caName", "issuerName");

        certificateManagementRemoveCrlExtCaHandler.process(command);
    }

}
