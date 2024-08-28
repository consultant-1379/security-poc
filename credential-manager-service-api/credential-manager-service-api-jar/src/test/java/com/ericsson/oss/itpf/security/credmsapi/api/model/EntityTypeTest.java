/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class EntityTypeTest {

    @Test
    public void testEntityType() {

        EntityType entityType = EntityType.ENTITY;

        assertTrue(entityType.getValue().equalsIgnoreCase("entity"));
        assertTrue(EntityType.fromValue("entity").equals(EntityType.ENTITY));
        EntityType wrong = null;
        try {
            wrong = EntityType.fromValue("fakeValue");
            assertTrue(false);
        } catch (IllegalArgumentException e) {
            assertTrue(true && wrong == null);
        }

    }
}