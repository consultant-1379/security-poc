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
package com.ericsson.oss.itpf.security.pki.manager.rest.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;

/**
 * Class for building dummy {@link EntityCategory} object for test cases
 * 
 * @author tcspred
 * 
 */
public class EntityCategorySetUpToTest {

    List<EntityCategory> entityCategories = new ArrayList<EntityCategory>();

    public EntityCategorySetUpToTest() {
        fillEntityCategories();
    }

    public List<EntityCategory> getEntityCategories() {
        return entityCategories;
    }

    private void fillEntityCategories() {
        entityCategories.add(getEntityCategory("service"));
        entityCategories.add(getEntityCategory("node-oam"));
        entityCategories.add(getEntityCategory("node-ipsec"));
    }

    private EntityCategory getEntityCategory(final String name) {
        final EntityCategory entityCategory = new EntityCategory();

        entityCategory.setId(1);
        entityCategory.setModifiable(true);
        entityCategory.setName(name);

        return entityCategory;
    }
}
