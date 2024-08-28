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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.trustprofile;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

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
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.TrustProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link TrustProfileResource}
 * 
 * @author xhemgan
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class TrustProfileResourceTest {

    @InjectMocks
    TrustProfileResource trustprofileResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(TrustProfileResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ProfileManagementServiceLocal profileManagementServiceLocal;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    private final static int STATUS_OK = 200;

    TrustProfile trustProfile;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    ObjectMapperUtilTest testObjectMapperUtil;

    /**
     * Method for setting up test data
     * 
     * @throws IOException
     */
    @Before
    public void setUp() throws Exception {

        final TrustProfileSetUpToTest trustProfileSetUpToTest = new TrustProfileSetUpToTest();
        trustProfile = trustProfileSetUpToTest.getTrustProfile();
        testObjectMapperUtil = new ObjectMapperUtilTest();

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_SERIALIZER_MAPPER)).thenReturn(
                testObjectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_SERIALIZER_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_DESERIALIZER_MAPPER)).thenReturn(
                testObjectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_DESERIALIZER_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService);

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(trustprofileResource);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching {@link TrustProfile}
     * 
     */
    @Test
    public void testGetProfile() throws Exception {

        Mockito.when(profileManagementService.getProfile(Mockito.any(TrustProfile.class))).thenReturn(trustProfile);

        request = MockHttpRequest.get("/trustprofile/load/1");

        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(trustProfile), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());

    }

    /**
     * Method to test the rest service for updating {@link TrustProfile}
     * 
     */
    @Test
    public void testUpdateProfile() throws Exception {

        Mockito.when(profileManagementService.updateProfile(Mockito.any(TrustProfile.class))).thenReturn(trustProfile);

        request = MockHttpRequest.put("/trustprofile/update");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(trustProfile).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(trustProfile), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for saving {@link TrustProfile}
     * 
     */
    @Test
    public void testSaveProfile() throws Exception {

        trustProfile.setId(0);
        Mockito.when(profileManagementService.createProfile(Mockito.any(TrustProfile.class))).thenReturn(trustProfile);

        request = MockHttpRequest.post("/trustprofile/save");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(getJsonFromObject(trustProfile).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(trustProfile), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for fetching list of active {@link TrustProfile}
     * 
     */
    @Test
    public void testFetch() throws Exception {

        final Profiles profiles = new Profiles();
        final List<TrustProfile> trustProfileList = new ArrayList<TrustProfile>();
        trustProfileList.add(trustProfile);
        profiles.setTrustProfiles(trustProfileList);

        Mockito.when(profileManagementServiceLocal.fetchActiveProfilesIdAndName(ProfileType.TRUST_PROFILE)).thenReturn(profiles);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_ID_NAME_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_ID_NAME_MAPPER));
        request = MockHttpRequest.get("/trustprofile/fetch");
        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());

    }

    private String getJsonFromObject(final TrustProfile trustProfile) throws JsonProcessingException {
        final ObjectMapper mapper = testObjectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_SERIALIZER_MAPPER);
        return mapper.writeValueAsString(trustProfile);
    }
}
