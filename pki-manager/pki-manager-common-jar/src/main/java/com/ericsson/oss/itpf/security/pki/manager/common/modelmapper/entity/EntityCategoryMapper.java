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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;

public class EntityCategoryMapper {

    @Inject
    private Logger logger;

    /**
     * Maps the EntityCategory API model to its corresponding JPA model
     * 
     * @param APIModel
     *            EntityCategory Object which should be converted to JPA model EntityCategoryData
     * 
     * @return Returns the JPA model of the given API model
     * 
     */
    @SuppressWarnings("unchecked")
    public EntityCategoryData fromAPIToModel(final EntityCategory APIModel) {

        final EntityCategory category = (EntityCategory) APIModel;
        final EntityCategoryData categoryData = new EntityCategoryData();

        categoryData.setId(category.getId());
        categoryData.setName(category.getName());
        categoryData.setModifiable(category.isModifiable());

        logger.debug("Mapped EntityCategoryData EntityCategory is {}", categoryData);
        return categoryData;
    }

    /**
     * Maps the EntityCategoryData JPA model to its corresponding API model
     * 
     * @param dataModel
     *            EntityCategoryData Object which should be converted to API model EntityCategory
     * 
     * @return Returns the API model of the given JPA model
     * 
     */
    @SuppressWarnings("unchecked")
    public EntityCategory toAPIFromModel(final EntityCategoryData dataModel) {

        final EntityCategory category = new EntityCategory();
        final EntityCategoryData categoryData = (EntityCategoryData) dataModel;

        category.setId(categoryData.getId());
        category.setName(categoryData.getName());
        category.setModifiable(categoryData.isModifiable());


        return category;

    }
}
