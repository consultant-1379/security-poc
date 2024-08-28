/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ws.rs.core.MediaType;
import javax.xml.datatype.DatatypeConfigurationException;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.json.JSONArray;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.adapter.ProfilesFilterAdapter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.validators.DTOValidator;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.AbstractProfileFetchSerializer;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.X509CertificateSerializer;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link ProfilesResource}
 * 
 * 
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfilesResourceTest {

    @InjectMocks
    ProfilesResource profilesResource;

    @Spy
    Logger logger = LoggerFactory.getLogger(ProfilesResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ProfileManagementServiceLocal profileManagementServiceLocal;

    @Mock
    DTOValidator dtoValidator;

    @Mock
    ProfilesFilterAdapter profilesFilterAdapter;

    @Mock
    CommonUtil commonUtil;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    ObjectMapperUtilTest testObjectMapperUtil;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    CertificateProfile certificateProfile;
    CertificateProfileSetUpToTest certificateProfileSetUpToTest;
    List<CertificateProfile> certProfielList = new ArrayList<CertificateProfile>();
    Profiles profiles = new Profiles();
    JSONArray certProfilesArray;

    private final static int STATUS_OK = 200;

    @Before
    public void setUp() throws DatatypeConfigurationException, IOException {

        testObjectMapperUtil = new ObjectMapperUtilTest();

        certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certProfielList.add(certificateProfile);
        profiles.setCertificateProfiles(certProfielList);

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(profilesResource);
        response = new MockHttpResponse();

        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        mapper.registerModule(module);

        certProfilesArray = new JSONArray(mapper.writeValueAsString(profiles.getCertificateProfiles()));
    }

    /**
     * Method to test rest service used for getting count of profiles in positive scenario
     */

    @Test
    public void testProfilesCount() throws UnsupportedEncodingException, URISyntaxException {

        final ProfileFilterDTO profileFilterDTO = getProfileFilterDTO();

        final ProfilesFilter profilesFilter = getProfilesFilter();
        Mockito.when(dtoValidator.validateProfileFilterDTO(profileFilterDTO)).thenReturn(true);
        Mockito.when(profilesFilterAdapter.toProfilesFilter(profileFilterDTO)).thenReturn(profilesFilter);
        Mockito.when(profileManagementServiceLocal.getProfilesCountByFilter(profilesFilter)).thenReturn(1);

        request = MockHttpRequest.post("/profiles/count");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(profileFilterDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(String.valueOf(1), response.getContentAsString());
        assertEquals(response.getStatus(), STATUS_OK);
    }

    /**
     * Method to test rest service used for getting count of profiles in negative scenario
     */

    @Test
    public void testProfilesCountInvalidDTO() throws UnsupportedEncodingException, URISyntaxException {

        final ProfileFilterDTO profileFilterDTO = getProfileFilterDTO();

        final ProfilesFilter profilesFilter = getProfilesFilter();
        Mockito.when(dtoValidator.validateProfileFilterDTO(profileFilterDTO)).thenReturn(false);
        Mockito.when(profilesFilterAdapter.toProfilesFilter(profileFilterDTO)).thenReturn(profilesFilter);

        request = MockHttpRequest.post("/profiles/count");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(profileFilterDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(String.valueOf(0), response.getContentAsString());
        assertEquals(response.getStatus(), STATUS_OK);
    }

    /**
     * Method to test rest service used for getting different type profiles in positive scenario
     * 
     * @throws DatatypeConfigurationException
     *             ,UnsupportedEncodingException, URISyntaxException
     * @throws IOException 
     * @throws JsonProcessingException 
     */

    @Test
    public void testProfilesFetch() throws URISyntaxException, DatatypeConfigurationException, JsonProcessingException, IOException {

        final ProfilesDTO profilesDTO = getProfilesDTO();

        final List<AbstractProfile> profileDetails = new ArrayList<AbstractProfile>();

        profileDetails.add(certificateProfile);

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.CERTIFICATE_PROFILE);
        types.add(ProfileType.ENTITY_PROFILE);
        profilesFilter.setType(types);

        Mockito.when(dtoValidator.validateProfilesDTO(profilesDTO)).thenReturn(true);
        Mockito.when(profilesFilterAdapter.toProfilesFilter(profilesDTO)).thenReturn(profilesFilter);
        Mockito.when(profileManagementServiceLocal.getProfileDetails(profilesFilter)).thenReturn(profileDetails);

        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(AbstractProfile.class, new AbstractProfileFetchSerializer());

        mapper.registerModule(module);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.PROFILES_FETCH_MAPPER)).thenReturn(mapper);

        request = MockHttpRequest.post("/profiles");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(profilesDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        final JsonNode expectedResult = mapper.readTree("[{\"id\":123,\"status\":\"active\",\"name\":\"TestCP\",\"type\":\"CERTIFICATE_PROFILE\"}]");
        final JsonNode actualResult = mapper.readTree(response.getContentAsString());
        assertEquals(expectedResult, actualResult); 
        assertEquals(response.getStatus(), STATUS_OK);
    }

    @Test
    public void testProfilesFetchNotValidDTO() throws UnsupportedEncodingException, URISyntaxException, DatatypeConfigurationException {

        final ProfilesDTO profilesDTO = getProfilesDTO();

        final List<AbstractProfile> profileDetails = new ArrayList<AbstractProfile>();

        profileDetails.add(certificateProfile);

        final ProfilesFilter profilesFilter = getProfilesFilter();

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.CERTIFICATE_PROFILE);
        types.add(ProfileType.ENTITY_PROFILE);
        profilesFilter.setType(types);

        Mockito.when(dtoValidator.validateProfilesDTO(profilesDTO)).thenReturn(false);
        Mockito.when(profilesFilterAdapter.toProfilesFilter(profilesDTO)).thenReturn(profilesFilter);
        Mockito.when(profileManagementServiceLocal.getProfileDetails(profilesFilter)).thenReturn(profileDetails);

        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        module.addSerializer(AbstractProfile.class, new AbstractProfileFetchSerializer());

        mapper.registerModule(module);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.PROFILES_FETCH_MAPPER)).thenReturn(mapper);

        request = MockHttpRequest.post("/profiles");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(profilesDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);
        assertNotNull(response.getContentAsString());
        assertEquals(response.getStatus(), STATUS_OK);

    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfilesDTO getProfilesDTO() {

        final ProfilesDTO profilesDTO = new ProfilesDTO();
        profilesDTO.setLimit(10);
        profilesDTO.setOffset(1);
        profilesDTO.setFilter(getProfileFilterDTO());
        return profilesDTO;
    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfilesFilter getProfilesFilter() {

        final ProfilesFilter profilesFilter = new ProfilesFilter();
        profilesFilter.setLimit(10);
        profilesFilter.setOffset(1);
        profilesFilter.setName("Test%");

        final com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter status = new com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfileStatusFilter();
        status.setActive(true);
        status.setInactive(true);

        profilesFilter.setStatus(status);

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilesFilter.setType(types);

        return profilesFilter;
    }

    /**
     * Test Data SetUP for ProfileFilterDTO.
     */
    private ProfileFilterDTO getProfileFilterDTO() {

        final ProfileFilterDTO profilefilterDTO = new ProfileFilterDTO();

        profilefilterDTO.setName("Test%");

        final ProfileStatusFilter status = new ProfileStatusFilter();
        status.setActive(true);
        status.setInactive(true);

        profilefilterDTO.setStatus(status);

        final List<ProfileType> types = new ArrayList<ProfileType>();

        types.add(ProfileType.CERTIFICATE_PROFILE);

        profilefilterDTO.setType(types);

        return profilefilterDTO;
    }

}
