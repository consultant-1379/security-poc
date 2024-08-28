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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import static org.mockito.Mockito.when;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;

@RunWith(MockitoJUnitRunner.class)
public class EntityOtpExpirationValidatorTest {
    @InjectMocks
    EntityOtpExpirationValidator entityOtpExpirationValidator;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    @EntityQualifier(EntityType.ENTITY)
    EntitiesPersistenceHandler<Entity> entityPersistenceHandler;

    private final static String NAME_PATH = "entityInfoData.name";

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityOtpExpirationValidator.class);

    Entity entity;

    @Before
    public void setUp() {
        entity = new Entity();
        entity.setOtpValidityPeriod(0);
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setId(1);
        entityInfo.setName("entity");
        entity.setEntityInfo(entityInfo);
    }

    @Test
    public void testOtpExpiration() {
        final EntityData entityData = getEntityData(30);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        Mockito.when(entitiesPersistenceHandler.getEntityByName(entity.getEntityInfo().getName(), EntityData.class, NAME_PATH)).thenReturn(entityData);
        entityOtpExpirationValidator.validate(entity);
    }

    @Test
    public void testOtpExpiration_ForExistingEntity() throws OTPExpiredException {
        final EntityData entityData = getEntityData(-1);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        Mockito.when(entitiesPersistenceHandler.getEntityByName(entity.getEntityInfo().getName(), EntityData.class, NAME_PATH)).thenReturn(entityData);
        entityOtpExpirationValidator.validate(entity);
    }

    @Test(expected = OTPExpiredException.class)
    public void testInvalidOtpExpiration() throws OTPExpiredException {
        final EntityData entityData = getEntityData(-5);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        Mockito.when(entitiesPersistenceHandler.getEntityByName(entity.getEntityInfo().getName(), EntityData.class, NAME_PATH)).thenReturn(entityData);
        entityOtpExpirationValidator.validate(entity);
    }

    private EntityData getEntityData(final Integer otpExpirationInterval) {
        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityData.setOtpValidityPeriod(otpExpirationInterval);
        entityData.setOtpGeneratedTime(new Date());
        entityInfoData.setOtp("12345");
        entityInfoData.setOtpCount(5);
        entityData.setEntityInfoData(entityInfoData);
        return entityData;
    }
}
