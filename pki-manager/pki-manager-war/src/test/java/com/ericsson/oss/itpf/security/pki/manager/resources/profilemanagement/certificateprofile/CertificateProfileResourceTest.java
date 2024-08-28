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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.certificateprofile;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.core.MediaType;
import javax.xml.datatype.DatatypeConfigurationException;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.powermock.api.mockito.PowerMockito;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.X509CertificateSerializer;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Test class for {@link CertificateProfileResource}
 * 
 * @author xhemgan
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileResourceTest {

    @InjectMocks
    CertificateProfileResource certificateProfileService;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertificateProfileResource.class);

    @Mock
    ProfileManagementServiceLocal profileManagementServiceLocal;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    EntityManagementService entityManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    CertificateProfile certificateProfile;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    ObjectMapperUtilTest testObjectMapperUtil;

    /**
     * Method for setting up test data.
     */
    @Before
    public void setUp() throws Exception {
        final CertificateProfileSetUpToTest certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        testObjectMapperUtil = new ObjectMapperUtilTest();

        Mockito.when(entityManagementService.getEntity(Mockito.any(CAEntity.class))).thenReturn(null);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER));
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getEntityManagementService()).thenReturn(entityManagementService); 
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService); 

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(certificateProfileService);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching {@link CertificateProfile}
     * 
     */
    @Test
    public void testGetProfile() throws Exception {

        Mockito.when(profileManagementService.getProfile(Mockito.any(CertificateProfile.class))).thenReturn(certificateProfile);

        request = MockHttpRequest.get("/certificateprofile/load/123");

        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(certificateProfile), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());

    }

    /**
     * Method to test the rest service for updating {@link CertificateProfile}
     * 
     */
    @Test
    public void testUpdateProfile() throws Exception {

        Mockito.when(profileManagementService.updateProfile(Mockito.any(CertificateProfile.class))).thenReturn(certificateProfile);

        request = MockHttpRequest.put("/certificateprofile/update");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certificateProfile).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(certificateProfile), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for saving {@link CertificateProfile}
     * 
     */
    @Test
    public void testSaveProfile() throws Exception {

        certificateProfile.setId(0);
        certificateProfile.setId(123);
        Mockito.when(profileManagementService.createProfile(Mockito.any(CertificateProfile.class))).thenReturn(certificateProfile);

        request = MockHttpRequest.post("/certificateprofile/save");
        request.contentType(MediaType.APPLICATION_JSON);
        request.content(JsonUtil.getJsonFromObject(certificateProfile).getBytes("UTF-8"));
        dispatcher.invoke(request, response);

        assertEquals(getJsonFromObject(certificateProfile), response.getContentAsString());
        assertEquals(STATUS_OK, response.getStatus());
    }

    /**
     * Method to test the rest service for fetching list of active {@link CertificateProfile}
     * 
     */
    @Test
    public void testFetchProfiles() throws DatatypeConfigurationException, URISyntaxException, IOException {
        final CertificateProfileSetUpToTest certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        final List<CertificateProfile> certProfielList = new ArrayList<CertificateProfile>();
        final Profiles profiles = new Profiles();

        final CertificateProfile certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certProfielList.add(certificateProfile);
        profiles.setCertificateProfiles(certProfielList);

        final ObjectMapperUtilTest testObjectMapperUtil = new ObjectMapperUtilTest();
        PowerMockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_PROFILE_ID_NAME_MAPPER)).thenReturn(
                testObjectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_PROFILE_ID_NAME_MAPPER));

        Mockito.when(profileManagementServiceLocal.fetchActiveProfilesIdAndName(ProfileType.CERTIFICATE_PROFILE)).thenReturn(profiles);
        request = MockHttpRequest.get("/certificateprofile/fetch");

        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), 200);
    }

    private String getJsonFromObject(final CertificateProfile certificateProfile) throws JsonProcessingException {
        final ObjectMapper mapper = new ObjectMapper();
        final SimpleModule module = new SimpleModule();
        module.addSerializer(X509Certificate.class, new X509CertificateSerializer());
        mapper.registerModule(module);

        return mapper.writeValueAsString(certificateProfile);
    }
}
