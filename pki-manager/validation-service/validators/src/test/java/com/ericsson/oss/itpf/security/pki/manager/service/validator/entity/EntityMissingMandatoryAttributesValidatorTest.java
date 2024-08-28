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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityMissingMandatoryAttributesValidatorTest {

    @Mock
    Logger logger;

    @InjectMocks
    EntityMissingMandatoryAttributesValidator entityMissingMandatoryAttributesValidator;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    SubjectValidator subjectValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    Entity entity;

    EntityData entityData;

    EntityProfileData entityProfileData;
    Map<String, Object> entityProfileMap = new HashMap<String, Object>();

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public <T extends AbstractSubjectAltNameFieldValue> void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entity = entitiesSetUpData.getEntity();
        entityData = entitiesSetUpData.getEntityData();
        entityProfileData = entityData.getEntityProfileData();
        entityProfileMap.put("name", "ENMRootCAEntityProfile");
        entityProfileMap.put("active", Boolean.TRUE);
        entityProfileData.getCertificateProfileData().setForCAEntity(false);
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenReturn(
                entityData.getEntityCategoryData());
    }

    /**
     * Method to test validate method in negative scenario.When providing EntityInfo name is null.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testCANameNull() {
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(null);
        entity.setEntityInfo(entityInfo);
        entityMissingMandatoryAttributesValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing EntityInfo name is empty.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testCANameEmpty() {
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName("  ");
        entity.setEntityInfo(entityInfo);
        entityMissingMandatoryAttributesValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing Subject and SubjectAltName with null values.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateWithSubjectAndSANNull() {
        entity.getEntityInfo().setSubject(null);
        entity.getEntityInfo().setSubjectAltName(null);
        entityMissingMandatoryAttributesValidator.validate(entity);
    }

    /**
     * Method to test validate method in negative scenario.When providing Subject and SubjectAltName fields with null values.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateWithSubjectFieldsAndSANFieldsNull() {
        entity.getEntityInfo().getSubject().setSubjectFields(null);
        entity.getEntityInfo().getSubjectAltName().setSubjectAltNameFields(null);
        entityMissingMandatoryAttributesValidator.validate(entity);
    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        entityMissingMandatoryAttributesValidator.validate(entity);

        Mockito.verify(logger).debug("Completed Validating Mandatory params for Entity {}", entity.getEntityInfo().getName());

    }

}
