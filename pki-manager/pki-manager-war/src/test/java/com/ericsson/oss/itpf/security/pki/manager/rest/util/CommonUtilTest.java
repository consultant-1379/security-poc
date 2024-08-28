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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.ws.rs.core.Response;
import javax.xml.datatype.DatatypeConfigurationException;

import org.json.JSONArray;
import org.json.JSONException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link CommonUtil}
 * 
 * @author xhemgan
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class CommonUtilTest {

    @InjectMocks
    CommonUtil commonUtil;

    @Spy
    Logger logger = LoggerFactory.getLogger(CommonUtil.class);

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    LoadErrorProperties loadErrorProperties;

    ObjectMapperUtilTest testObjectMapperUtil;
    JSONArray certProfilesArray;
    String certProfileArrayExpected;

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    final String revocationInfoJsonString = "{\"entityName\":\"TestCA\",\"revocationReason\":\"AA_COMPROMISE\"}";
    final String certificatesRevocationInfoJsonArray = "[{\"serialNumber\":\"346b8fb241e5e93f\",\"issuer\":\"CN=ARJ_Root\",\"subject\":\"CN=ARJ_Root\",\"revocationReason\":\"7\"},{\"serialNumber\":\"346b8fb3451e5e93f\",\"issuer\":\"CN=ARJ_Root\",\"subject\":\"CN=ARJ_Root\",\"revocationReason\":\"10\"}]";

    /**
     * Method for setting up test data
     * 
     * @throws Exception
     */
    @Before
    public void setUp() throws Exception {

        final CertificateProfileSetUpToTest certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        final List<CertificateProfile> certProfielList = new ArrayList<CertificateProfile>();
        final Profiles profiles = new Profiles();
        final ObjectMapper mapper = new ObjectMapper();

        testObjectMapperUtil = new ObjectMapperUtilTest();
        final CertificateProfile certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certProfielList.add(certificateProfile);
        profiles.setCertificateProfiles(certProfielList);

        certProfilesArray = new JSONArray(mapper.writeValueAsString(profiles.getCertificateProfiles()));
        certProfileArrayExpected = new JSONArray(mapper.writeValueAsString(profiles.getCertificateProfiles())).toString();
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.ERROR_MESSAGE_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.ERROR_MESSAGE_MAPPER));
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService);
    }

    /**
     * Method to test whether the given error message is returning the corresponding JSON string with error messge and its ID.
     */
    @Test
    public void testGetJSONErrorMessage() {

        final String expectedJson = "{\"code\":11003,\"message\":\"Exception while retrieving supported algorithms\"}";
        final String errorMessage = "Exception while retrieving supported algorithms";

        final ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
        errorMessageDTO.setCode("11003");
        errorMessageDTO.setMessage(errorMessage);

        Mockito.when(loadErrorProperties.getErrorMessageDTO(errorMessage)).thenReturn(errorMessageDTO);

        assertEquals(expectedJson, commonUtil.getJSONErrorMessage(errorMessage));
    }

    /**
     * Method to test whether the given error message is returning the corresponding JSON string with error messge and its ID.
     */
    @Test
    public void testGetJSONErrorMessageWithException() {

        final String expectedJson = "{\"code\":11001,\"message\":\"An unexpected internal system error occurred. Please check logs.\"}";
        final String errorMessage = "Exception while retrieving supported algorithms";

        final ErrorMessageDTO errorMessageDTO = new ErrorMessageDTO();
        errorMessageDTO.setCode("11003");
        errorMessageDTO.setMessage(errorMessage);

        Mockito.when(loadErrorProperties.getErrorMessageDTO(errorMessage)).thenThrow(new IllegalArgumentException());

        assertEquals(expectedJson, commonUtil.getJSONErrorMessage(errorMessage));
    }

    /**
     * Method to test whether the object with given attribute is placed at the first in a JSON array.
     */
    @Test
    public void testPlaceAttributeAtFirst() {

        final String certProfileArrayActual = commonUtil.placeAttributeAtFirst(certProfilesArray, AttributeType.ID, "123");

        assertEquals(certProfileArrayExpected, certProfileArrayActual);
    }

    /**
     * Method to test whether the object with given attribute is placed at the first in a JSON array.
     */
    @Test
    public void testPlaceAttributeAtFirstUnknown() {

        final String certProfileArrayActual = commonUtil.placeAttributeAtFirst(certProfilesArray, AttributeType.ID, "1");

        assertEquals(certProfileArrayExpected, certProfileArrayActual);
    }

    @Test
    public void testGetExtendedKeyUsage() {

        final List<String> extendedKeyUsages = new ArrayList<String>();
        extendedKeyUsages.add("1.3.6.1.5.5.7.3.1");

        commonUtil.getExtendedKeyUsage(extendedKeyUsages);

    }

    @Test
    public void testGetCRLDistributionPoint() throws CertificateException, IOException {

        final SetUPData setUPData = new SetUPData();
        final X509Certificate x509Certificate = setUPData.getX509Certificate("certificates/RootCA.crt");

        commonUtil.getCRLDistributionPoint(x509Certificate);

    }

    @Test
    public void testPlaceAttributeAtFirstForEntities() throws JSONException, JsonProcessingException {

        JSONArray entitiesArray;
        final ObjectMapper mapper = new ObjectMapper();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        List<Entity> entityList = entitiesSetUpData.getEntityList();
        Entity entity = entityList.get(0);
        Entities entities = new Entities();
        entities.setEntities(entityList);
        entitiesArray = new JSONArray(mapper.writeValueAsString(entities.getEntities()));
        String result = commonUtil.placeAttributeAtFirstForEntities(entitiesArray, AttributeType.ID, "1");
        assertNotNull(result);
    }

    /**
     * Method to test for placeing the given attribute in the first row in the JSON array.
     */
    @Test
    public void testPlaceAttributeAtFirstForCAEntities() throws JSONException, JsonProcessingException {

        JSONArray caEntitiesArray;
        final ObjectMapper mapper = new ObjectMapper();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        List<CAEntity> entityList = entitiesSetUpData.getCaEntityList();
        CAEntity caentity = entityList.get(0);
        Entities entities = new Entities();
        entities.setCAEntities(entityList);
        caEntitiesArray = new JSONArray(mapper.writeValueAsString(entities.getCAEntities()));
        String result = commonUtil.placeAttributeAtFirstForEntities(caEntitiesArray, AttributeType.ID, "1");
        assertNotNull(result);
    }

    /**
     * Method to test for getting certificate Extensions
     */
    @Test
    public void testGetCertificateExtension() throws DatatypeConfigurationException {
        final CertificateProfileSetUpToTest certificateProfileSetUpToTest = new CertificateProfileSetUpToTest();
        final CertificateProfile certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        Mockito.when(profileManagementService.getProfile(Mockito.any(CertificateProfile.class))).thenReturn(certificateProfile);

        assertNotNull(commonUtil.getCertificateExtension(1, certificateProfile.getCertificateExtensions().getCertificateExtensions().get(0).getClass()));
    }

    @Test
    public void testGetRevocationInfoDTO() throws IOException {
        ObjectMapperType objectMapperType = ObjectMapperType.REVOCATION_REASON_DESERIALIZER_MAPPER;
        Mockito.when(objectMapperUtil.getObjectMapper(objectMapperType)).thenReturn(testObjectMapperUtil.getObjectMapper(objectMapperType));
        EntityRevocationInfoDTO entityRevocationInfoDTO = commonUtil.getRevocationInfoDTO(EntityRevocationInfoDTO.class, revocationInfoJsonString);
        assertNotNull(entityRevocationInfoDTO);
        assertEquals("TestCA", entityRevocationInfoDTO.getEntityName());
        assertEquals(RevocationReason.AA_COMPROMISE, entityRevocationInfoDTO.getRevocationReason());
    }

    @Test
    public void testProduceJsonResponse() throws JsonProcessingException {
        ObjectMapperType objectMapperType = ObjectMapperType.COMMON_MAPPER;
        Mockito.when(objectMapperUtil.getObjectMapper(objectMapperType)).thenReturn(testObjectMapperUtil.getObjectMapper(objectMapperType));
        final Response response = commonUtil.produceJsonResponse(Arrays.asList(new RevocationStatusDTO()));
        assertNotNull(response);
        assertEquals(207, response.getStatus());
    }

    @Test
    public void testGetRevocationInfoDTOList() throws JSONException, IOException {
        ObjectMapperType objectMapperType = ObjectMapperType.REVOCATION_REASON_DESERIALIZER_MAPPER;
        Mockito.when(objectMapperUtil.getObjectMapper(objectMapperType)).thenReturn(testObjectMapperUtil.getObjectMapper(objectMapperType));
        List<CertificateRevocationInfoDTO> certificateRevocationInfoDTOs = commonUtil.getRevocationInfoDTOList(CertificateRevocationInfoDTO.class, certificatesRevocationInfoJsonArray);
        assertNotNull(certificateRevocationInfoDTOs);
        assertEquals(2, certificateRevocationInfoDTOs.size());
        assertEquals("346b8fb241e5e93f", certificateRevocationInfoDTOs.get(0).getSerialNumber());
        assertEquals("346b8fb3451e5e93f", certificateRevocationInfoDTOs.get(1).getSerialNumber());

    }
}
