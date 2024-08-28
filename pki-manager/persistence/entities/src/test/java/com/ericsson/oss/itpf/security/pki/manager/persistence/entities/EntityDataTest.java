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

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class EntityDataTest {

    EntityData entityData;

    @Before
    public void setup() {
        EntityDataSetUp entityDataSetUp = new EntityDataSetUp();
        entityData = entityDataSetUp.createEntityData();

    }

    @Test
    public void testEntityData() {

        entityData.getId();
        entityData.getKeyGenerationAlgorithm();
        entityData.getEntityCategoryData();
        assertNotNull(entityData.getCertificateExpiryNotificationDetailsData());
        assertNotNull(entityData.getEntityInfoData());

        entityData.getEntityProfileData();
        entityData.onCreate();
        entityData.onUpdate();

        assertNotNull(entityData);
    }

}
