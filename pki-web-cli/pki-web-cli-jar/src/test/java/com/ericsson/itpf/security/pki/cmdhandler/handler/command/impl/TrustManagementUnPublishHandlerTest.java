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
public class TrustManagementUnPublishHandlerTest {

    @InjectMocks
    TrustManagementUnPublishHandler trustManagementUnPublishHandler;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Mock
    CliUtil cliUtil;

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Spy
    final Logger logger = LoggerFactory.getLogger(TrustManagementPublishHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command = null;
    Map<String, Object> properties = new HashMap<String, Object>();

    private static final String SUCCESS_MESSAGE_EE = "End Entity certificates are unpublished successfully from Trust Distribution Point Service.";
    private static final String SUCCESS_MESSAGE_CA = "CA Entity certificates are unpublished successfully.";

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
    public void testProcessUnPublishCertificateForCAEntity() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementUnPublishHandler.process(command);
        assertEquals(commandResponse.getMessage(), SUCCESS_MESSAGE_CA);
    }

    @Test
    public void testProcessUnPublishCertificateForEntity() {
        properties.put("entityname", "ENTITY");
        properties.put("entitytype", "ee");
        command.setProperties(properties);
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementUnPublishHandler.process(command);
        assertEquals(commandResponse.getMessage(), SUCCESS_MESSAGE_EE);
    }

    @Test
    public void testProcessEntityNotFoundException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);

        Mockito.when(trustManagementUnPublishHandler.process(command)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementUnPublishHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Invalid argument value: Entity doesn't exist"));
    }

    @Test
    public void testProcessCertificateServiceException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);

        Mockito.when(trustManagementUnPublishHandler.process(command)).thenThrow(new CertificateServiceException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementUnPublishHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcessException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);

        Mockito.when(trustManagementUnPublishHandler.process(command)).thenThrow(new RuntimeException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementUnPublishHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testUnPublishCertificateForCAEntity_SecurityViolationException() {
        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        Mockito.doThrow(SecurityViolationException.class).when(caCertificateManagementService).unPublishCertificate(command.getValueString("entityname"));
        trustManagementUnPublishHandler.process(command);
    }

    @Test
    public void testUnPublishCertificateForEntity_SecurityViolationException() {
        properties.put("entityname", "ENTITY");
        properties.put("entitytype", "ee");
        command.setProperties(properties);
        Mockito.doThrow(SecurityViolationException.class).when(caCertificateManagementService).unPublishCertificate(command.getValueString("entityname"));
        trustManagementUnPublishHandler.process(command);
    }
}
