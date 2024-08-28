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

import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryValidatorTest {
    @Spy
    final private Logger logger = LoggerFactory.getLogger(EntityCategoryValidator.class);

    @InjectMocks
    EntityCategoryValidator entityCategoryValidator;

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
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenReturn(entityData.getEntityCategoryData());
    }

    /**
     * Method to test validate method in negative scenario. When providing category name with Empty value.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testWithCategoryNameEmpty() {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("  ");
        entity.setCategory(entityCategory);
        entityCategoryValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario. When providing category name with Null value.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testWithCategoryNameNull() {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName(null);

        entity.setCategory(entityCategory);

        entityCategoryValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario. When providing invalid category .
     */
    @Test(expected = InvalidEntityCategoryException.class)
    public void testWithInvalidCategory() {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("entity");
        entity.setCategory(entityCategory);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenReturn(null);
        entityCategoryValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario. Whether service exception is throwing While Validating the category .
     */
    @Test(expected = EntityServiceException.class)
    public void testServiceExceptionWhileValidatingCategory() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenThrow(PersistenceException.class);
        entityCategoryValidator.validate(entity);

    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        entityCategoryValidator.validate(entity);

    }

}
