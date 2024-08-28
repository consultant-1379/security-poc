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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

/**
 * This class acts as builder for {@link EntityCategorySetUpData}
 */
public class EntityCategorySetUpData {
    /**
     * Method that returns valid EntityCategory
     * 
     * @return OtherName
     */
    public EntityCategory getEntityCategory() {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setModifiable(true);
        entityCategory.setName("NODE");
        return entityCategory;
    }

}
