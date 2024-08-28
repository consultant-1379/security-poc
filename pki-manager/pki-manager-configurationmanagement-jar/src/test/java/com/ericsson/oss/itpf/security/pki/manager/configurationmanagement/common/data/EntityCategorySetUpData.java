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
package com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.common.data;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

public class EntityCategorySetUpData {

    EntityCategory category;
    EntityCategory categoryWithName;
    EntityCategory categoryWithId;
    EntityCategoryData categoryData;

    public EntityCategory createEntityCategorySetupData(long id, String name, boolean modifiable) {
        category = new EntityCategory();
        if (id != 0)
            category.setId(1);
        if (name != null)
            category.setName(name);
        category.setModifiable(modifiable);
        return category;
    }

    public EntityCategory createEntityCategorySetupDataWithId() {
        categoryWithId = new EntityCategory();
        categoryWithId.setId(1);
        categoryWithId.setModifiable(true);
        return categoryWithId;
    }

    public EntityCategoryData createEntityCategoryData(String name, boolean modifiable) {
        categoryData = new EntityCategoryData();
        categoryData.setName(name);
        categoryData.setModifiable(modifiable);
        return categoryData;
    }

    // public EntityCategoryData createEntityCategoryDataWithModifiableFalse(){
    // categoryData = new EntityCategoryData();
    // categoryData.setName("category");
    // categoryData.setModifiable(false);
    // return categoryData;
    // }

    private EntityData prepareEntityDataWithStatusActive() {
        EntityData entityData = new EntityData();
        EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setStatus(EntityStatus.ACTIVE);
        entityData.setEntityCategoryData(createEntityCategoryData("category", true));
        entityData.setEntityInfoData(entityInfoData);

        return entityData;
    }

    private EntityData prepareEntityDataWithStatusDeleted() {
        EntityData entityData = new EntityData();
        EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setStatus(EntityStatus.DELETED);
        entityData.setEntityCategoryData(createEntityCategoryData("category", true));
        entityData.setEntityInfoData(entityInfoData);

        return entityData;
    }

    public List<EntityData> createEntityDataListWithStatusDeleted() {
        List<EntityData> entityDataList = new ArrayList<EntityData>();

        entityDataList.add(prepareEntityDataWithStatusDeleted());
        return entityDataList;
    }

    public List<EntityData> createEntityDataListWithStatusActive() {
        List<EntityData> entityDataList = new ArrayList<EntityData>();

        entityDataList.add(prepareEntityDataWithStatusActive());
        return entityDataList;
    }

    public List<EntityProfileData> createEntityProfileDataListWithStatusActive() {
        List<EntityProfileData> entityProfileDataList = new ArrayList<EntityProfileData>();
        EntityProfileData entityProfileData = new EntityProfileData();
        entityProfileData.setEntityCategory(createEntityCategoryData("category", true));
        entityProfileData.setActive(true);
        entityProfileDataList.add(entityProfileData);

        return entityProfileDataList;
    }
}
