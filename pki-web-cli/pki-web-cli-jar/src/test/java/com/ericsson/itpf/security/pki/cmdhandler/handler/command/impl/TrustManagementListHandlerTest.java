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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class TrustManagementListHandlerTest {

    @InjectMocks
    TrustManagementListHandler trustManagementListHandler;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CommandHandlerUtils commandHandlerUtils;


    @Mock
    CliUtil cliUtil;

    @Spy
    final Logger logger = LoggerFactory.getLogger(TrustManagementListHandler.class);

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    Map<String, Object> properties = new HashMap<String, Object>();
    private String entityName = "ENMROOTCA";
    private String entityTypeValue = "ca";
    private List<TrustedEntityInfo> trustedEntityInfoList = new ArrayList<TrustedEntityInfo>();
    private TrustedEntityInfo trustedEntityInfo;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        properties.put("command", "TRUSTMANAGEMENTLIST");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.TRUSTMANAGEMENTLIST);
        properties.put("type", "entitytype");
        properties.put("name", "entityname");
        command.setProperties(properties);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);
    }

    @Test
    public void testProcessForCAEntity() {
        setTrustedEntityInfo();
        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, entityName)).thenReturn(trustedEntityInfoList);
        trustManagementListHandler.process(command);
        final PkiCommandResponse pkiCommandResponse = trustManagementListHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.NAME_MULTIPLE_VALUE);
    }

    @Test
    public void testProcessForEntityNameNull() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.ENTITY)).thenReturn(trustedEntityInfoList);
        trustManagementListHandler.process(command);
        final PkiCommandResponse pkiCommandResponse = trustManagementListHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.NAME_MULTIPLE_VALUE);
    }

    @Test
    public void testProcessForEntityServiceException() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.ENTITY)).thenThrow(new EntityServiceException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("retry"));

    }

    @Test
    public void testProcessForCertificateNotFoundException() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.ENTITY)).thenThrow(new CertificateNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Certificate not found for the entity"));

    }

    @Test
    public void testProcessForTrustDistributionPointURLNotFoundException() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.ENTITY)).thenThrow(new TrustDistributionPointURLNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));

    }

    @Test
    public void testProcessForIllegalArgumentException() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.ENTITY)).thenThrow(new IllegalArgumentException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));

    }

    @Test
    public void testProcessForException() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.ENTITY)).thenThrow(new RuntimeException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));

    }

    @Test
    public void testProcessEntityNotFoundException() {

        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        command.setProperties(properties);
        Mockito.when(trustManagementListHandler.process(command)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListHandler.process(command);
        assertEquals(commandResponse.getErrorCode(), 11203);
    }

    @Test
    public void testProcessForCAEntity_SecurityViolationException() {
        setTrustedEntityInfo();
        properties.put("entityname", "ENMROOTCA");
        properties.put("entitytype", "ca");
        trustedEntityInfoList.add(trustedEntityInfo);
        command.setProperties(properties);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, entityName)).thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        trustManagementListHandler.process(command);
    }

    private TrustedEntityInfo setTrustedEntityInfo() {
        trustedEntityInfo = new TrustedEntityInfo();
        trustedEntityInfo.setEntityType(EntityType.ENTITY);
        trustedEntityInfo.setEntityName("ca");
        trustedEntityInfo.setIssuerDN("issuerDN");
        trustedEntityInfo.setTrustDistributionPointURL("trustDistributionPointURL");
        trustedEntityInfo.setCertificateSerialNumber("1001");
        trustedEntityInfo.setCertificateStatus(CertificateStatus.ACTIVE);
        return trustedEntityInfo;
    }
}
