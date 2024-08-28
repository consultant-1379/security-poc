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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
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
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.AttributeType;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ProfileListDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.X509CertificateSerializer;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link ProfileListResource}
 * 
 * @author xhemgan
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class ProfileListResourceTest extends TestUtil {

    @InjectMocks
    ProfileListResource profileList;

    @Spy
    Logger logger = LoggerFactory.getLogger(ProfileListResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    CommonUtil commonUtil;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;
    private final static String PROFILE_DELETED = "Profile deleted Successfully.";

    CertificateProfile certificateProfile;
    List<CertificateProfile> certProfielList = new ArrayList<CertificateProfile>();
    Profiles profiles = new Profiles();
    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;
    JSONArray certProfilesArray;
    ObjectMapperUtilTest testObjectMapperUtil;

    /**
     * Method for setting up test data.
     */
    @Before
    public void setup() throws DatatypeConfigurationException, IOException {

        final CertificateProfileSetUpToTest certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();

        testObjectMapperUtil = new ObjectMapperUtilTest();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certProfielList.add(certificateProfile);
        profiles.setCertificateProfiles(certProfielList);

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(profileList);
        response = new MockHttpResponse();

        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        mapper.registerModule(module);

        certProfilesArray = new JSONArray(mapper.writeValueAsString(profiles.getCertificateProfiles()));
        certProfilesArray = updateProfileTypeWithValue(certProfilesArray);
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService); 

    }

    /**
     * Method to test rest service for deleting certificate profile
     */
    @Test
    public void testProfielListDeleteCP() throws URISyntaxException, UnsupportedEncodingException {

        request = MockHttpRequest.delete("/1.0/profilelist/delete/CERTIFICATE_PROFILE/1");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(PROFILE_DELETED, response.getContentAsString());
    }

    /**
     * Method to test rest service for deleting trust profile
     */
    @Test
    public void testProfielListDeleteTP() throws URISyntaxException, UnsupportedEncodingException {

        request = MockHttpRequest.delete("/1.0/profilelist/delete/TRUST_PROFILE/1");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(PROFILE_DELETED, response.getContentAsString());
    }

    /**
     * Method to test rest service for deleting entity profile
     */
    @Test
    public void testProfielListDeleteEP() throws URISyntaxException, UnsupportedEncodingException {

        request = MockHttpRequest.delete("/1.0/profilelist/delete/ENTITY_PROFILE/1");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(PROFILE_DELETED, response.getContentAsString());
    }

    /**
     * Method to test rest service for fetching all the profiles
     */
    @Test
    public void testProfielListFetch() throws URISyntaxException, UnsupportedEncodingException {
        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.TRUST_PROFILE);
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);

        final ProfileListDTO profileListDTO = new ProfileListDTO();
        profileListDTO.setId("1");

        Mockito.when(profileManagementService.exportProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]))).thenReturn(profiles);
        Mockito.when(commonUtil.mergeJsonArray(Mockito.any(JSONArray.class), Mockito.any(JSONArray.class), Mockito.any(JSONArray.class))).thenReturn(certProfilesArray);
        Mockito.when(commonUtil.placeAttributeAtFirst(certProfilesArray, AttributeType.ID, "1")).thenReturn(certProfilesArray.toString());
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER));

        request = MockHttpRequest.post("/1.0/profilelist/fetch");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(profileListDTO).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(certProfilesArray.toString(), response.getContentAsString());
        assertEquals(response.getStatus(), STATUS_OK);
    }

}
