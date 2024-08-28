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
package com.ericsson.oss.itpf.security.pki.manager.rest.dto;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * This class will test CAEntityProfileResourceTest
 * 
 * @author tcsrav
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityListDTOTest {

    @Test
    public void testEquals() {

        EntityListDTO e1 = new EntityListDTO();
        e1.setId("01");
        assertEquals(e1.getId(), "01");

    }
}
