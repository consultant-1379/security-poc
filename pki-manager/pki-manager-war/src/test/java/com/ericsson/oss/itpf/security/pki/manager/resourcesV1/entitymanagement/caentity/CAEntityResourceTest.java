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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement.caentity;

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
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.setup.CAEntitySetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link CAEntityResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class CAEntityResourceTest {

    @InjectMocks
    CAEntityResource caEntityResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(CAEntityResource.class);

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    CAEntity caEntity;

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

        final CAEntitySetUpToTest caEntitySetUpToTest = new CAEntitySetUpToTest();
        caEntity = caEntitySetUpToTest.getCAEntity();

        testObjectMapperUtil = new ObjectMapperUtilTest();
        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(caEntityResource);
        response = new MockHttpResponse();

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_DESERIALIZER_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_DESERIALIZER_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_FETCH_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_FETCH_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getEntityManagementService()).thenReturn(entityManagementService); 

    }

    /**
     * Method to test the rest service for fetching {@link CAEntity}
     * 
     */
    @Test
    public void testGetCAEntity() throws Exception {

        Mockito.when(entityManagementService.getEntity(Mockito.any(CAEntity.class))).thenReturn(caEntity);

        request = MockHttpRequest.get("/1.0/caentity/load/1");

        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(caEntity), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for updating {@link CAEntity}
     * 
     */
    @Test
    public void testUpdateCAEntity() throws Exception {

        Mockito.when(entityManagementService.updateEntity(Mockito.any(CAEntity.class))).thenReturn(caEntity);

        request = MockHttpRequest.put("/1.0/caentity/update");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(caEntity).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(caEntity), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for saving {@link CAEntity}
     * 
     */
    @Test
    public void testSaveCAEntity() throws Exception {

        caEntity.getCertificateAuthority().setId(0);
        Mockito.when(entityManagementService.createEntity(Mockito.any(CAEntity.class))).thenReturn(caEntity);

        request = MockHttpRequest.post("/1.0/caentity/save");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(caEntity).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(caEntity), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    private String getJsonFromObject(final CAEntity caEntity) throws JsonProcessingException {
        final ObjectMapper mapper = testObjectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_FETCH_MAPPER);

        return mapper.writeValueAsString(caEntity);
    }
}
