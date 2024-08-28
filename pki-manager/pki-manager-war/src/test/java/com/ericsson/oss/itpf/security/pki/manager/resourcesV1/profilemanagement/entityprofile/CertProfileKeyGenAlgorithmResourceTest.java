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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.entityprofile;

import static org.junit.Assert.assertEquals;

import java.net.URISyntaxException;
import java.util.List;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.AlgorithmSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link CertProfileKeyGenAlgorithmResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class CertProfileKeyGenAlgorithmResourceTest {

    @InjectMocks
    CertProfileKeyGenAlgorithmResource certProfileKeyGenAlgorithmService;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertProfileKeyGenAlgorithmResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;
    @Mock
    PKIManagerEServiceProxy pkiManagerEServiceProxy;
    private final static int STATUS_OK = 200;

    CertificateProfile certificateProfile;
    List<Algorithm> algorithmsList;
    String jsonAlgorithms;

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
        final AlgorithmSetUpToTest algorithmSetUpToTest = new AlgorithmSetUpToTest();
        final ObjectMapper mapper = new ObjectMapper();

        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        algorithmsList = algorithmSetUpToTest.getKeyGenerationAlgorithmList();
        jsonAlgorithms = mapper.writeValueAsString(algorithmsList);
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService); 

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(certProfileKeyGenAlgorithmService);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching Key Generation Algorithms in Certificate profile of given id
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException {

        Mockito.when(profileManagementService.getProfile(Mockito.any(CertificateProfile.class))).thenReturn(certificateProfile);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_GEN_ALGORITHM_SEIALIZER_MAPPER)).thenReturn(new ObjectMapper());

        request = MockHttpRequest.get("/1.0/certprofilekeygenalgorithm/fetch/1");

        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(jsonAlgorithms, response.getContentAsString());
    }
}
