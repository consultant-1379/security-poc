/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.validator;

import static org.mockito.Mockito.when;

import javax.persistence.PersistenceException;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.common.data.EntityCategorySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.PKIConfigurationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;

@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryValidatorTest {

    @InjectMocks
    EntityCategoryValidator entityCategoryValidator;

    @Mock
    PersistenceManager persistenceManager;

    static EntityCategorySetUpData entityCategorySetUpData;

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityCategoryValidator.class);

    static EntityCategory category;
    static EntityCategory category1;
    static EntityCategoryData categoryData;
    static EntityCategoryData categoryData1;

    @BeforeClass
    public static void prepareEntityCategoryObject() {
        entityCategorySetUpData = new EntityCategorySetUpData();
        category = entityCategorySetUpData.createEntityCategorySetupData(0, "category", true);

        category1 = entityCategorySetUpData.createEntityCategorySetupData(0, "categ$ory1", true);

        categoryData = entityCategorySetUpData.createEntityCategoryData("category", false);

        categoryData1 = entityCategorySetUpData.createEntityCategoryData("category1", true);
    }

    @Test
    public void testValidateEntityCategoryDuringCreate() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, category.getName(), "name")).thenReturn(null);
        entityCategoryValidator.validateCreate(category);
    }

    @Test(expected = EntityCategoryAlreadyExistsException.class)
    public void testEntityCategoryAlreadyExists() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, category.getName(), "name")).thenReturn(categoryData);
        entityCategoryValidator.validateCreate(category);
    }

    @Test(expected = EntityCategoryException.class)
    public void testValidateCreateNullEntityCategory() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, category.getName(), "name")).thenReturn(null);
        entityCategoryValidator.validateCreate(null);
    }

    @Test(expected = InvalidEntityCategoryException.class)
    public void testValidateEntityCategoryDuringUpdate() {
        when(persistenceManager.findEntity(EntityCategoryData.class, category.getId())).thenReturn(null);
        entityCategoryValidator.validateUpdate(category);
    }

    @Test(expected = InvalidEntityCategoryException.class)
    public void testValidateEntityCategoryException() {
        when(persistenceManager.findEntity(EntityCategoryData.class, category.getId())).thenReturn(categoryData);
        entityCategoryValidator.validateUpdate(category);
    }

    @Test(expected = EntityCategoryAlreadyExistsException.class)
    public void testCategoryNameAvailabilityDuringUpdate() {
        when(persistenceManager.findEntity(EntityCategoryData.class, category.getId())).thenReturn(categoryData1);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, category.getName(), "name")).thenReturn(categoryData1);
        entityCategoryValidator.validateUpdate(category);
    }

    @Test(expected = PKIConfigurationServiceException.class)
    public void testValidatePersistenceException() {
        when(persistenceManager.findEntity(EntityCategoryData.class, category.getId())).thenThrow(new PersistenceException());
        entityCategoryValidator.validateUpdate(category);
    }

}
