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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.common.EServiceRefProxy;
import com.ericsson.itpf.security.pki.cmdhandler.util.CliUtil;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

@RunWith(MockitoJUnitRunner.class)
public class TrustManagementPublishHandlerTest {

    @InjectMocks
    TrustManagementPublishHandler trustManagementPublishHandler;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(TrustManagementPublishHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command = null;
    Map<String, Object> properties = new HashMap<String, Object>();

    private static final String SUCCESS_MESSAGE_EE = "All valid End entity certificates published successfully to Trust Distribution Point Service";
    private static final String SUCCESS_MESSAGE_CA = "All valid CA Entity certificates published successfully to Trust Distribution Point service";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        properties.put("command", "TRUSTMANAGEMENTPUBLISH");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.TRUSTMANAGEMENTPUBLISH);
        properties.put("type", "entitytype");
        properties.put("name", "entityname");
        command.setProperties(properties);
        Mockito.when(eServiceRefProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);
        Mockito.when(eServiceRefProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);
    }

    @Test
    public void testProcessPublishCertificateForCAEntity() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementPublishHandler.process(command);
        assertEquals(commandResponse.getMessage(), SUCCESS_MESSAGE_CA);
    }

    @Test
    public void testProcessPublishCertificateForEntity() {
        properties.put("entityname", "ENTITY");
        properties.put("entitytype", "ee");
        command.setProperties(properties);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementPublishHandler.process(command);
        assertEquals(commandResponse.getMessage(), SUCCESS_MESSAGE_EE);
    }

    @Test
    public void testProcessEntityNotFoundException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);

        Mockito.when(trustManagementPublishHandler.process(command)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementPublishHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Invalid argument value: Entity doesn't exist"));
    }

    @Test
    public void testProcessCertificateServiceException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        Mockito.when(trustManagementPublishHandler.process(command)).thenThrow(new CertificateServiceException());
        trustManagementPublishHandler.process(command);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementPublishHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        Mockito.when(trustManagementPublishHandler.process(command)).thenThrow(new RuntimeException());
        trustManagementPublishHandler.process(command);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementPublishHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testPublishCertificateForCAEntity_SecurityViolationException() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        Mockito.doThrow(SecurityViolationException.class).when(caCertificateManagementService).publishCertificate(command.getValueString("entityname"));
        trustManagementPublishHandler.process(command);
    }

    @Test
    public void testPublishCertificateForEntity_SecurityViolationException() {
        properties.put("entityname", "ENTITY");
        properties.put("entitytype", "ee");
        command.setProperties(properties);
        Mockito.doThrow(SecurityViolationException.class).when(caCertificateManagementService).publishCertificate(command.getValueString("entityname"));
        trustManagementPublishHandler.process(command);
    }
}
