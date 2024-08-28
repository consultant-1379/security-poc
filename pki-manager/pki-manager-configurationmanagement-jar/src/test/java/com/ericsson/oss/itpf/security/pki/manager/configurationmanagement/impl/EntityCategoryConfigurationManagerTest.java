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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.impl;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.EntityCategoryPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.common.data.EntityCategorySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.validator.EntityCategoryValidator;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryConfigurationManagerTest {

    @InjectMocks
    EntityCategoryConfigurationManager entityCategoryConfigurationManager;

    @Mock
    EntityCategoryValidator entityCategoryValidator;

    @Mock
    EntityCategoryPersistenceHandler entityCategoryPersistenceHandler;

    static EntityCategorySetUpData entityCategorySetUpData;

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityCategoryConfigurationManagerTest.class);

    private static EntityCategory category;

    static List<EntityCategory> entityCategoryList = new ArrayList<EntityCategory>();

    @BeforeClass
    public static void preCondition() {
        entityCategorySetUpData = new EntityCategorySetUpData();

        category = entityCategorySetUpData.createEntityCategorySetupData(0, "category1", false);
        entityCategoryList.add(category);
    }

    @Test
    public void testCreateEntityCategory() {
        logger.info("CATEGORY DATA IN CREATE TEST CASE ----- " + category.getName() + "   " + category.isModifiable());
        entityCategoryValidator.validateCreate(category);
        when(entityCategoryPersistenceHandler.createEntityCategory(category)).thenReturn(category);
        assertEquals(entityCategoryConfigurationManager.createEntityCategory(category), category);

    }

    @Test
    public void testUpdateEntityCategory() {
        entityCategoryValidator.validateUpdate(category);
        when(entityCategoryPersistenceHandler.updateEntityCategory(category)).thenReturn(category);
        assertEquals(entityCategoryConfigurationManager.updateEntityCategory(category), category);
    }

    @Test
    public void testGetEntityCategory() {
        when(entityCategoryPersistenceHandler.getEntityCategory(category)).thenReturn(category);
        assertEquals(entityCategoryConfigurationManager.getEntityCategory(category), category);
    }

    @Test
    public void testDeleteEntityCategory() {
        entityCategoryConfigurationManager.deleteEntityCategory(category);
        verify(entityCategoryPersistenceHandler).deleteEntityCategory(category);
    }

    @Test
    public void testIsNameAvailable() {
        when(entityCategoryPersistenceHandler.isNameAvailable(category.getName())).thenReturn(true);
        assertEquals(entityCategoryConfigurationManager.isNameAvailable(category.getName()), true);
    }

    @Test
    public void testGetEntityCategories() {
        when(entityCategoryPersistenceHandler.getCategories()).thenReturn(entityCategoryList);
        assertEquals(entityCategoryConfigurationManager.getEntityCategories(), entityCategoryList);
        ;
    }
}
