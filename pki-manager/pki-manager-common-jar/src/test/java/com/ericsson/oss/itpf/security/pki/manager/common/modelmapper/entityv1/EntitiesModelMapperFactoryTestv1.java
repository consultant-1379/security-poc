/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.CAEntityModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntitiesModelMapperFactoryv1;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class EntitiesModelMapperFactoryTestv1 {
    @InjectMocks
    EntitiesModelMapperFactoryv1 entityModelMapperFactory;

    @Mock
    CAEntityModelMapper caEntityModelMapper;

    @Mock
    EntityModelMapper entityModelMapper;

    @Test
    public void testGetEntityMapper() {
        assertEquals(entityModelMapperFactory.getEntitiesMapper(EntityType.ENTITY), entityModelMapper);
    }

    @Test
    public void testGetCAEntityMapper() {
        assertEquals(entityModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY), caEntityModelMapper);
    }

    @Test(expected = NullPointerException.class)
    public void testgetEntitiesMapperNull() {
        entityModelMapperFactory.getEntitiesMapper(null);
    }
}
