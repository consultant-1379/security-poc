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

import javax.inject.Inject;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link CertProfileSubjectFieldTypeResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class CertProfileSubjectFieldTypeResourceTest {

    @InjectMocks
    CertProfileSubjectFieldTypeResource certProfileSubjectFieldTypeService;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertProfileSubjectFieldTypeResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    CommonUtil commonUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    CertificateProfile certificateProfile;
    List<SubjectFieldType> subjectFieldTypes;
    String jsonSubjectFieldTypes;
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
        final ObjectMapper mapper = new ObjectMapper();

        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        subjectFieldTypes = certificateProfileSetUpToTest.getSubjectFieldTypes();
        jsonSubjectFieldTypes = mapper.writeValueAsString(subjectFieldTypes);
        Mockito.when(pkiManagerEServiceProxy.getProfileManagementService()).thenReturn(profileManagementService); 


        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(certProfileSubjectFieldTypeService);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching subject alt name in Certificate profile of given id
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException {

        Mockito.when(profileManagementService.getProfile(Mockito.any(CertificateProfile.class))).thenReturn(certificateProfile);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_CAPABILITIES_MAPPER)).thenReturn(new ObjectMapper());

        request = MockHttpRequest.get("/1.0/certprofilesubjectfieldtype/fetch/1");

        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(jsonSubjectFieldTypes, response.getContentAsString());
    }
}
