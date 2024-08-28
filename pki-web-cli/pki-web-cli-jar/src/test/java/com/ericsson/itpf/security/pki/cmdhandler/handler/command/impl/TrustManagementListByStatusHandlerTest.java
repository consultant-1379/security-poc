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

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class TrustManagementListByStatusHandlerTest {

    @InjectMocks
    TrustManagementListByStatusHandler trustManagementListByStatusHandler;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    EServiceRefProxy eServiceRefProxy;

    @Mock
    CommandHandlerUtils commandHandlerUtils;

    @Mock
    CliUtil cliUtil;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    PkiPropertyCommand command;
    Map<String, Object> properties = new HashMap<String, Object>();
    List<TrustedEntityInfo> trustedEntityInfoList = new ArrayList<TrustedEntityInfo>();
    private static TrustedEntityInfo trustedEntityInfo;
    private static String entityTypeValue = "ca";
    private static String status = "active";

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        properties.put("command", "TRUSTMANAGEMENTLISTBYSTATUS");
        command = new PkiPropertyCommand();
        command.setCommandType(PkiCommandType.TRUSTMANAGEMENTLISTBYSTATUS);
        properties.put("type", "entitytype");
        properties.put("status", "certstatus");
        command.setProperties(properties);
        Mockito.when(eServiceRefProxy.getEntityManagementService()).thenReturn(entityManagementService);

    }

    @Test
    public void testProcesCertStatusActive() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        trustedEntityInfoList.add(trustedEntityInfo);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenReturn(trustedEntityInfoList);
        final PkiCommandResponse pkiCommandResponse = trustManagementListByStatusHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.NAME_MULTIPLE_VALUE);
    }

    @Test
    public void testProcesCertStatusActiveNull() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenReturn(trustedEntityInfoList);
        final PkiCommandResponse pkiCommandResponse = trustManagementListByStatusHandler.process(command);
        assertEquals(pkiCommandResponse.getResponseType(), PKICommandResponseType.MESSAGE);
    }

    @Test
    public void testProcesCertStatusActiveForEntityEntityServiceException() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenThrow(new EntityServiceException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListByStatusHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Unable to List Certificates"));
    }

    @Test
    public void testProcesCertStatusActiveEntityNotFoundException() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenThrow(new EntityNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListByStatusHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Invalid argument value: Entity doesn't exist"));
    }

    @Test
    public void testProcesCertStatusActiveTrustDistributionPointURLNotFoundException() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenThrow(new TrustDistributionPointURLNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListByStatusHandler.process(command);
        assertTrue(commandResponse.getMessage().contains(""));
    }

    @Test
    public void testProcesCertificateNotFoundException() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListByStatusHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Certificate not found for the entity"));
    }

    @Test
    public void testProcesIllegalArgumentException() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenThrow(new IllegalArgumentException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListByStatusHandler.process(command);
        assertTrue(commandResponse.getMessage().contains("Unsupported PKI command argument"));
    }

    @Test
    public void testProcesException() {
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenThrow(new RuntimeException());
        final PkiMessageCommandResponse commandResponse = (PkiMessageCommandResponse) trustManagementListByStatusHandler.process(command);
        assertEquals(command.getValueString(Constants.ENTITY_TYPE), "ca");
    }

    @Test
    public void testProcesCertStatusActive_SecurityViolationException() {
        setTrustedEntityInfo();
        properties.put("entitytype", "ca");
        properties.put("certstatus", "active");
        trustedEntityInfoList.add(trustedEntityInfo);
        Mockito.when(commandHandlerUtils.getEntityType(entityTypeValue)).thenReturn(EntityType.CA_ENTITY);
        Mockito.when(commandHandlerUtils.getCertificateStatus(status)).thenReturn(CertificateStatus.ACTIVE);
        Mockito.when(entityManagementService.getTrustedEntitiesInfo(EntityType.CA_ENTITY, CertificateStatus.ACTIVE))
                .thenThrow(new SecurityViolationException(PkiErrorCodes.SECURITY_VIOLATION_EXCEPTION));
        trustManagementListByStatusHandler.process(command);
    }

    private TrustedEntityInfo setTrustedEntityInfo() {
        trustedEntityInfo = new TrustedEntityInfo();
        trustedEntityInfo.setEntityType(EntityType.CA_ENTITY);
        trustedEntityInfo.setEntityName("ca");
        trustedEntityInfo.setIssuerDN("issuerDN");
        trustedEntityInfo.setSubjectDN("subjectDN");
        trustedEntityInfo.setTrustDistributionPointURL("trustDistributionPointURL");
        trustedEntityInfo.setCertificateSerialNumber("1001");
        trustedEntityInfo.setCertificateStatus(CertificateStatus.ACTIVE);
        return trustedEntityInfo;
    }
}
