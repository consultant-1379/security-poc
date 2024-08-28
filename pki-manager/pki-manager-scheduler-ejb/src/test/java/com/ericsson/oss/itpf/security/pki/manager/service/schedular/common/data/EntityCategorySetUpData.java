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
package com.ericsson.oss.itpf.security.pki.manager.service.schedular.common.data;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;

/**
 *
 * This class is used to set the data for Entity Category
 */
public class EntityCategorySetUpData {

    private static final int ID = 1;
    private static final String NAME = "EndEntity";

    private EntityCategory entityCategory;
    private EntityCategoryData entityCategoryData;

    /**
     *
     */
    public EntityCategorySetUpData() {
        fillEntityCategory();
        fillEntityCategoryData();
    }

    /**
     * @param id
     * @param name
     * @param modifiable
     * @return EntityCategory
     */
    public EntityCategory createEntityCategorySetupData(final long id, final String name, final boolean modifiable) {
        entityCategory = new EntityCategory();
        if (id != 0) {
            entityCategory.setId(1);
        }
        if (name != null) {
            entityCategory.setName(name);
        }
        entityCategory.setModifiable(modifiable);
        return entityCategory;
    }

    /**
     * @param name
     * @param modifiable
     * @return EntityCategoryData
     */
    public EntityCategoryData createEntityCategoryData(final String name, final boolean modifiable) {
        entityCategoryData = new EntityCategoryData();
        entityCategoryData.setName(name);
        entityCategoryData.setModifiable(modifiable);
        return entityCategoryData;
    }

    private void fillEntityCategory() {
        entityCategory = new EntityCategory();
        entityCategory.setId(ID);
        entityCategory.setModifiable(true);
        entityCategory.setName(NAME);
    }

    private void fillEntityCategoryData() {
        entityCategoryData = new EntityCategoryData();
        entityCategoryData.setId(ID);
        entityCategoryData.setModifiable(true);
        entityCategoryData.setName(NAME);
    }

    /**
     * @return the entityCategory
     */
    public EntityCategory getEntityCategory() {
        return entityCategory;
    }

    /**
     * @return the entityCategoryData
     */
    public EntityCategoryData getEntityCategoryData() {
        return entityCategoryData;
    }

}
