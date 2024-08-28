package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementConfigCRLExtCAHandlerTest {

    @InjectMocks
    CertificateManagementConfigCRLExtCAHandler certificateManagementConfigCrlExtCaHandler;

    @Mock
    ExtCACRLManagementService extCaCrlManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateManagementImportExtCAHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;

    Map<String, Object> properties = new HashMap<String, Object>();

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        MockitoAnnotations.initMocks(this);

        properties.put("command", "EXTERNALCACONFIGCRL");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.EXTERNALCACONFIGCRL);
        Mockito.when(eServiceRefProxy.getExtCaCrlManagementService()).thenReturn(extCaCrlManagementService);
    }

    @Test
    public void testProcessCommandConfigCRLExtCA_enable() {
        properties.put("name", "caName");
        properties.put("autoupdate", "enable");
        properties.put("timer", "5");
        command.setProperties(properties);

        final PkiCommandResponse pkiCommandResponse = certificateManagementConfigCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandConfigCRLExtCA_disable() {
        properties.put("name", "caName");
        properties.put("autoupdate", "disable");
        properties.put("timer", "5");
        command.setProperties(properties);

        final PkiCommandResponse pkiCommandResponse = certificateManagementConfigCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandConfigCRLExtCA_error() {

        properties.put("autoupdate", "disable");
        properties.put("timer", "5");
        command.setProperties(properties);

        Mockito.doThrow(MissingMandatoryFieldException.class).when(extCaCrlManagementService).configExternalCRLInfo(Mockito.anyString(), Mockito.anyBoolean(), Mockito.anyInt());
        final PkiCommandResponse pkiCommandResponse = certificateManagementConfigCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandConfigCRLExtCA_error2() {

        properties.put("autoupdate", "disable");
        properties.put("timer", "5");
        command.setProperties(properties);

        Mockito.doThrow(ExternalCANotFoundException.class).when(extCaCrlManagementService).configExternalCRLInfo(Mockito.anyString(), Mockito.anyBoolean(), Mockito.anyInt());
        final PkiCommandResponse pkiCommandResponse = certificateManagementConfigCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandConfigCRLExtCA_error3() {

        properties.put("autoupdate", "disable");
        properties.put("timer", "5");
        command.setProperties(properties);

        Mockito.doThrow(ExternalCredentialMgmtServiceException.class).when(extCaCrlManagementService).configExternalCRLInfo(Mockito.anyString(), Mockito.anyBoolean(), Mockito.anyInt());
        final PkiCommandResponse pkiCommandResponse = certificateManagementConfigCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessCommandConfigCRLExtCA_error4() {

        properties.put("autoupdate", "disable");
        properties.put("timer", "5");
        command.setProperties(properties);

        Mockito.doThrow(Exception.class).when(extCaCrlManagementService).configExternalCRLInfo(Mockito.anyString(), Mockito.anyBoolean(), Mockito.anyInt());
        final PkiCommandResponse pkiCommandResponse = certificateManagementConfigCrlExtCaHandler.process(command);

        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcessUpdateCAExportCertHandler_SecurityViolationException() throws SecurityViolationException {
        properties.put("name", "caName");
        properties.put("autoupdate", "enable");
        properties.put("timer", "5");
        command.setProperties(properties);

        Mockito.doThrow(SecurityViolationException.class).when(extCaCrlManagementService).configExternalCRLInfo(Mockito.anyString(), Mockito.anyBoolean(), Mockito.anyInt());
        certificateManagementConfigCrlExtCaHandler.process(command);

    }
}
