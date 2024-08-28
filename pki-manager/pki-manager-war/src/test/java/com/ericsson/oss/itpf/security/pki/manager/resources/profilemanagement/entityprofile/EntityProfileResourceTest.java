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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.entityprofile;

import static org.junit.Assert.*;

import javax.inject.Inject;
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
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.EntityProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link EntityProfileResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityProfileResourceTest {

    @InjectMocks
    EntityProfileResource entityProfileResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityProfileResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    EntityProfile entityProfile;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    ObjectMapperUtilTest testObjectMapperUtil;

    /**
     * Method for setting up test data.
     */
    @Before
    public void setUp() throws Exception {

        final EntityProfileSetUpToTest entityProfileSetUpToTest = new EntityProfileSetUpToTest();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        testObjectMapperUtil = new ObjectMapperUtilTest();

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService); 

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(entityProfileResource);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching {@link EntityProfile}
     * 
     */
    @Test
    public void testGetProfile() throws Exception {

        Mockito.when(profileManagementService.getProfile(Mockito.any(EntityProfile.class))).thenReturn(entityProfile);

        request = MockHttpRequest.get("/entityprofile/load/1");

        dispatcher.invoke(request, response);

        assertNotNull(response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());

    }

    /**
     * Method to test the rest service for updating {@link EntityProfile}
     * 
     */
    @Test
    public void testUpdateProfile() throws Exception {

        Mockito.when(profileManagementService.updateProfile(Mockito.any(EntityProfile.class))).thenReturn(entityProfile);

        request = MockHttpRequest.put("/entityprofile/update");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(entityProfile).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertNotNull(response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for saving {@link EntityProfile}
     * 
     */
    @Test
    public void testSaveProfile() throws Exception {

        entityProfile.setId(0);
        Mockito.when(profileManagementService.createProfile(Mockito.any(EntityProfile.class))).thenReturn(entityProfile);

        request = MockHttpRequest.post("/entityprofile/save");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(entityProfile).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertNotNull(response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    private String getJsonFromObject(final EntityProfile entityProfile2) throws JsonProcessingException {
        final ObjectMapper mapper = testObjectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);

        return mapper.writeValueAsString(entityProfile2);
    }
}
