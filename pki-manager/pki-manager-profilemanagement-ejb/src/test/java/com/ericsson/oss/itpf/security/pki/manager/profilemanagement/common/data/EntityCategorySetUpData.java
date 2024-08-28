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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;

public class EntityCategorySetUpData {

    private static final int ID = 1;
    private static final String NAME = "EndEntity";
    public final static String NAME_PATH = "name";

    private EntityCategory entityCategory;
    private EntityCategoryData entityCategoryData;

    /**
	 * 
	 */
    public EntityCategorySetUpData() {
        fillEntityCategory();
        fillEntityCategoryData();
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
