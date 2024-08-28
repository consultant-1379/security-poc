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

public class EntitySummaryTest {

    @Test
    public void testEntitySummary() {

        // prepare data
        final String name = "name";
        final EntityStatus status = EntityStatus.ACTIVE;
        final Subject subject = new Subject();
        subject.setCommonName("commonName");
        
        // instantiate EntitySummary
        final EntitySummary entity = new EntitySummary(name, status, subject);
        
        // check
        assertTrue(name.equals(entity.getName()));
        assertTrue(entity.getStatus() == status);
        assertTrue("commonName".equals(entity.getSubject().getCommonName()));
        
        // modify values
        entity.setName("name2");
        entity.setStatus(EntityStatus.DELETED);
        entity.getSubject().setCommonName("commonName2");
        
        // second check
        // check
        assertTrue("name2".equals(entity.getName()));
        assertTrue(entity.getStatus() == EntityStatus.DELETED);
        assertTrue("commonName2".equals(entity.getSubject().getCommonName()));        
    }

}
