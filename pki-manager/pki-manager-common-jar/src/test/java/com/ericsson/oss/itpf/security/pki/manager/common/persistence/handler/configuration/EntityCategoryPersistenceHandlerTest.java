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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.util.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityCategorySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityCategoryMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryPersistenceHandlerTest {

    @InjectMocks
    EntityCategoryPersistenceHandler entityCategoryPersistenceHandler;

    @Mock
    EntityCategoryMapper entityCategoryMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityData entityData;

    EntityCategorySetUpData entityCategorySetUpData;

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityCategoryPersistenceHandler.class);

    static EntityCategory category;
    static EntityCategory categoryWithName;
    static EntityCategory categoryWithId;
    static EntityCategoryData categoryData;

    @Before
    public void prepareEntityCategoryObject() {

        entityCategorySetUpData = new EntityCategorySetUpData();
        category = entityCategorySetUpData.createEntityCategorySetupData(1, "category", true);

        categoryWithName = entityCategorySetUpData.createEntityCategorySetupData(0, "category", true);

        categoryWithId = entityCategorySetUpData.createEntityCategorySetupData(1, null, true);

        categoryData = entityCategorySetUpData.createEntityCategoryData("category", true);
    }

    @Test
    public void testCreateEntityCategory() {
        when(entityCategoryMapper.fromAPIToModel(category)).thenReturn(categoryData);
        persistenceManager.createEntity(categoryData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, category.getName(), "name")).thenReturn(categoryData);
        when(entityCategoryMapper.toAPIFromModel(categoryData)).thenReturn(category);
        assertEquals(entityCategoryPersistenceHandler.createEntityCategory(category), category);
    }

    @Test
    public void testUpdateEntityCategory() {
        when(entityCategoryMapper.fromAPIToModel(category)).thenReturn(categoryData);
        persistenceManager.updateEntity(categoryData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, category.getName(), "name")).thenReturn(categoryData);
        when(entityCategoryMapper.toAPIFromModel(categoryData)).thenReturn(category);
        assertEquals(entityCategoryPersistenceHandler.updateEntityCategory(category), category);
    }

    @Test
    public void testGetEntityCategoryByName() {

        when(persistenceManager.findEntityByName(EntityCategoryData.class, categoryWithName.getName(), "name")).thenReturn(categoryData);
        when(entityCategoryMapper.toAPIFromModel(categoryData)).thenReturn(categoryWithName);
        assertEquals(entityCategoryPersistenceHandler.getEntityCategory(categoryWithName), categoryWithName);
    }

    @Test
    public void testGetEntityCategoryById() {
        when(persistenceManager.findEntity(EntityCategoryData.class, 1)).thenReturn(categoryData);
        when(entityCategoryMapper.toAPIFromModel(categoryData)).thenReturn(categoryWithId);
        assertEquals(entityCategoryPersistenceHandler.getEntityCategory(categoryWithId), categoryWithId);
    }

    @Test(expected = EntityCategoryNotFoundException.class)
    public void testGetEntityCategoryById1() {
        when(persistenceManager.findEntity(EntityCategoryData.class, 1)).thenReturn(null);
        assertEquals(entityCategoryPersistenceHandler.getEntityCategory(categoryWithId), null);
    }

    @Test
    public void testGetEntityCategoryByNameAndId() {
        when(persistenceManager.findEntityByIdAndName(EntityCategoryData.class, 1, category.getName(), "name")).thenReturn(categoryData);
        when(entityCategoryMapper.toAPIFromModel(categoryData)).thenReturn(category);
        assertEquals(entityCategoryPersistenceHandler.getEntityCategory(category), category);
    }

    @Test
    public void testDeleteEntityCategory() {
        final Map<String, Object> entityAttributes = new HashMap<String, Object>();
        final List<EntityData> entityDataList = new ArrayList<EntityData>();
        final List<EntityProfileData> entityProfileDataList = new ArrayList<EntityProfileData>();

        when(persistenceManager.findEntityByIdAndName(EntityCategoryData.class, 1, category.getName(), "name")).thenReturn(categoryData);

        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityData.class, entityAttributes)).thenReturn(entityDataList);
        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityProfileData.class, entityAttributes)).thenReturn(entityProfileDataList);

        entityCategoryPersistenceHandler.deleteEntityCategory(category);
        verify(persistenceManager).deleteEntity(categoryData);

    }

    @Test
    public void testDeleteEntityCategoryMappedToEntity() {
        final Map<String, Object> entityAttributes = new HashMap<String, Object>();
        final List<EntityData> entityDataList = new ArrayList<EntityData>();
        final List<EntityProfileData> entityProfileDataList = new ArrayList<EntityProfileData>();
        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setStatus(EntityStatus.DELETED);

        entityData.setEntityCategoryData(categoryData);
        entityData.setEntityInfoData(entityInfoData);
        entityDataList.add(entityData);

        when(persistenceManager.findEntityByIdAndName(EntityCategoryData.class, 1, category.getName(), "name")).thenReturn(categoryData);

        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityData.class, entityAttributes)).thenReturn(entityDataList);
        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityProfileData.class, entityAttributes)).thenReturn(entityProfileDataList);

        entityCategoryPersistenceHandler.deleteEntityCategory(category);
        verify(persistenceManager).deleteEntity(categoryData);

    }

    @Test(expected = EntityCategoryInUseException.class)
    public void testDeleteEntityCategoryMappedToEntity1() {
        final Map<String, Object> entityAttributes = new HashMap<String, Object>();
        final List<EntityData> entityDataList = new ArrayList<EntityData>();
        final List<EntityProfileData> entityProfileDataList = new ArrayList<EntityProfileData>();
        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setStatus(EntityStatus.ACTIVE);

        entityData.setEntityCategoryData(categoryData);
        entityData.setEntityInfoData(entityInfoData);
        entityDataList.add(entityData);

        when(persistenceManager.findEntityByIdAndName(EntityCategoryData.class, 1, category.getName(), "name")).thenReturn(categoryData);

        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityData.class, entityAttributes)).thenReturn(entityDataList);
        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityProfileData.class, entityAttributes)).thenReturn(entityProfileDataList);

        entityCategoryPersistenceHandler.deleteEntityCategory(category);
        verify(persistenceManager).deleteEntity(categoryData);

    }

    @Test(expected = EntityCategoryInUseException.class)
    public void testDeleteEntityCategoryMappedToEntityProfile() {
        final Map<String, Object> entityAttributes = new HashMap<String, Object>();
        final List<EntityData> entityDataList = new ArrayList<EntityData>();
        final List<EntityProfileData> entityProfileDataList = new ArrayList<EntityProfileData>();
        final EntityProfileData entityProfileData = new EntityProfileData();
        entityProfileData.setEntityCategory(categoryData);
        entityProfileData.setActive(true);
        entityProfileDataList.add(entityProfileData);

        when(persistenceManager.findEntityByIdAndName(EntityCategoryData.class, 1, category.getName(), "name")).thenReturn(categoryData);

        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityData.class, entityAttributes)).thenReturn(entityDataList);
        entityAttributes.put("entityCategoryData", categoryData);
        when(persistenceManager.findEntitiesWhere(EntityProfileData.class, entityAttributes)).thenReturn(entityProfileDataList);

        entityCategoryPersistenceHandler.deleteEntityCategory(category);
        verify(persistenceManager).deleteEntity(categoryData);

    }

    @Test
    public void testIsNameAvailableReturningTrue() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, "category", "name")).thenReturn(null);
        assertEquals(entityCategoryPersistenceHandler.isNameAvailable("category"), true);
    }

    @Test
    public void testIsNameAvailableReturningFalse() {
        when(persistenceManager.findEntityByName(EntityCategoryData.class, "category", "name")).thenReturn(categoryData);
        assertEquals(entityCategoryPersistenceHandler.isNameAvailable("category"), false);
    }

    @Test
    public void testGetCategories() {
        final List<EntityCategory> entityCategoriesList = new ArrayList<EntityCategory>();
        final List<EntityCategoryData> entityCategoryDataList = new ArrayList<EntityCategoryData>();
        final EntityCategoryData categoryData = new EntityCategoryData();
        categoryData.setName("category");
        categoryData.setModifiable(true);
        entityCategoryDataList.add(categoryData);

        when(persistenceManager.getAllEntityItems(EntityCategoryData.class)).thenReturn(entityCategoryDataList);
        when(entityCategoryMapper.toAPIFromModel(categoryData)).thenReturn(category);
        entityCategoriesList.add(category);
        assertEquals(entityCategoryPersistenceHandler.getCategories(), entityCategoriesList);
    }
}
