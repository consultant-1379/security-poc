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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class EntitiesModelMapperFactoryTest {
    @InjectMocks
    EntitiesModelMapperFactory entityModelMapperFactory;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    EntityMapper entityMapper;

    @Test
    public void testGetEntityMapper() {
        assertEquals(entityModelMapperFactory.getEntitiesMapper(EntityType.ENTITY), entityMapper);
    }

    @Test
    public void testGetCAEntityMapper() {
        assertEquals(entityModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY), caEntityMapper);
    }

    @Test(expected = NullPointerException.class)
    public void testgetEntitiesMapperNull() {
        entityModelMapperFactory.getEntitiesMapper(null);
    }
}
