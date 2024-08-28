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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.entity;

import static org.junit.Assert.assertEquals;

import javax.ws.rs.core.MediaType;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup.EntitySetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link EntityResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityResourceTest {

    @InjectMocks
    EntityResource entityResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityResource.class);

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    Entity entity;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    ObjectMapperUtilTest testObjectMapperUtil;

    /**
     * Method for setting up test data
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {

        final EntitySetUpToTest entitySetUpToTest = new EntitySetUpToTest();
        entity = entitySetUpToTest.getEntity();

        testObjectMapperUtil = new ObjectMapperUtilTest();
        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(entityResource);
        response = new MockHttpResponse();

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_FETCH_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_FETCH_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getEntityManagementService()).thenReturn(entityManagementService); 

    }

    /**
     * Method to test the rest service for fetching {@link Entity}
     * 
     */
    @Test
    public void testGetEntity() throws Exception {

        Mockito.when(entityManagementService.getEntity(Mockito.any(Entity.class))).thenReturn(entity);

        request = MockHttpRequest.get("/entity/load/1");

        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(entity), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for updating {@link Entity}
     * 
     */
    @Test
    public void testUpdateEntity() throws Exception {

        Mockito.when(entityManagementService.updateEntity(Mockito.any(Entity.class))).thenReturn(entity);

        request = MockHttpRequest.put("/entity/update");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(entity).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(entity), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for saving {@link Entity}
     * 
     */
    @Test
    public void testSaveEntity() throws Exception {

        entity.getEntityInfo().setId(0);
        Mockito.when(entityManagementService.createEntity(Mockito.any(Entity.class))).thenReturn(entity);

        request = MockHttpRequest.post("/entity/save");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(entity).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(entity), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    private String getJsonFromObject(final Entity entity) throws JsonProcessingException {
        final ObjectMapper mapper = testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_FETCH_MAPPER);

        return mapper.writeValueAsString(entity);
    }
}
