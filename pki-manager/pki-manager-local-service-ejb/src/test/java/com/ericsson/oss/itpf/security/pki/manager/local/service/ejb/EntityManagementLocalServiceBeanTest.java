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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.upgrade.SyncMismatchEntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementLocalServiceBeanTest {

    @InjectMocks
    EntityManagementLocalServiceBean entityManagementLocalServiceBean;

    @Mock
    Logger logger;

    @Mock
    EntitiesManager entitiesManager;

    @Mock
    ValidationServiceUtils validateServiceUtils;

    @Mock
    ValidationService validationService;

    @Mock
    SyncMismatchEntitiesPersistenceHandler syncMismatchEntitiesPersistenceHandler;

    private final EntityInfo entityInfo = new EntityInfo();
    private final Entity entity = new Entity();
    private final String entityName = "NEW_ENTITY";
    private final String otp = "123456";
    private final String entitySubjectDN = "OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=NEW_ENTITY";
    private final String issuerDN = "OU=BUCI_DUAC_NAM,C=SE,O=ERICSSON,CN=NE_CA_NEW_ENTITY";

    @Before
    public void setUp() {
        entityInfo.setName(entityName);
        entityInfo.setId(0);
        entityInfo.setOTP(otp);
    }

    @Test
    public void testGetOTP() {
        entity.setEntityInfo(entityInfo);

        Mockito.when(entitiesManager.getOtp(entity)).thenReturn(otp);
        entityManagementLocalServiceBean.getOTP(entityName);
        Mockito.verify(entitiesManager).getOtp(entity);
    }

    @Test
    public void testIsOTPValid() {
        entity.setEntityInfo(entityInfo);

        Mockito.when(entitiesManager.isOTPValid(entityName, otp)).thenReturn(true);
        entityManagementLocalServiceBean.isOTPValid(entityName, otp);
        Mockito.verify(entitiesManager).isOTPValid(entityName, otp);
    }

    @Test
    public void testGetEntity() {
        entity.setEntityInfo(entityInfo);

        Mockito.when(entitiesManager.getEntity(entitySubjectDN, issuerDN)).thenReturn(entity);
        entityManagementLocalServiceBean.getEntity(entitySubjectDN, issuerDN);
        Mockito.verify(entitiesManager).getEntity(entitySubjectDN, issuerDN);
    }

    @Test
    public void testSyncMismatchEntities() {
        entityManagementLocalServiceBean.syncMismatchEntities();
    }

    @Test
    public void testSyncMismatchEntities_Exception() {
        Mockito.doThrow(Exception.class).when(syncMismatchEntitiesPersistenceHandler).syncMismatchEntities();
        entityManagementLocalServiceBean.syncMismatchEntities();
    }
}
