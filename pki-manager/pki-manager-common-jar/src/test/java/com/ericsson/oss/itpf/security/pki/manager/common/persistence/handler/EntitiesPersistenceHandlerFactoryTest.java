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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * Test class for {@link EntitiesPersistenceHandlerFactory}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class EntitiesPersistenceHandlerFactoryTest {

    @InjectMocks
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler<CAEntity> cAEntityPersistenceHandler;

    @Mock
    EntitiesPersistenceHandler<Entity> entityPersistenceHandler;

    /**
     * Method to test getEntitiesPersistenceHandler Method in positive scenario.
     */
    @Test
    public void testGetEntitiesPersistenceHandlerCAEntity() {
        assertEquals(cAEntityPersistenceHandler, entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY));
    }

    /**
     * Method to test getEntitiesPersistenceHandler Method in positive scenario.
     */
    @Test
    public void testGetEntitiesPersistenceHandlerEntity() {
        assertEquals(entityPersistenceHandler, entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY));
    }

    @Test(expected = NullPointerException.class)
    public void testEntitiesPersistenceHandlerNull() {
        entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(null);
    }

}
