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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class EntityCategoryDataTest {

    EntityCategoryData entityCategoryData;
    EntityCategoryData expectedEntityCategoryData;

    @Before
    public void setup() {

        entityCategoryData = getEntityCategoryData();
        expectedEntityCategoryData = getEntityCategoryData();
    }

    @Test
    public void testEntityCategoryForEquals() {

        entityCategoryData.hashCode();
        entityCategoryData.toString();
        entityCategoryData.getId();
        entityCategoryData.getName();
        entityCategoryData.isModifiable();

        assertTrue(entityCategoryData.equals(entityCategoryData));
        assertTrue(entityCategoryData.equals(expectedEntityCategoryData));

        entityCategoryData.equals(null);
        entityCategoryData.equals(new CrlGenerationInfoDataTest());
        entityCategoryData.setId(2);
        entityCategoryData.equals(expectedEntityCategoryData);
        entityCategoryData.setId(1);
        entityCategoryData.setModifiable(false);
        entityCategoryData.equals(expectedEntityCategoryData);
        entityCategoryData.setModifiable(true);
        entityCategoryData.setName("test");

        assertFalse(entityCategoryData.equals(expectedEntityCategoryData));

        entityCategoryData.setName(null);

        assertFalse(entityCategoryData.equals(expectedEntityCategoryData));

    }

    private EntityCategoryData getEntityCategoryData() {
        EntityCategoryData entityCategoryData = new EntityCategoryData();
        entityCategoryData.setId(1);
        entityCategoryData.setModifiable(true);
        entityCategoryData.setName("EndEntity");
        return entityCategoryData;
    }

}
