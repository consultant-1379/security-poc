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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link CertProfileKeyUsageTypeResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class CertProfileKeyUsageTypeResourceTest {

    @InjectMocks
    CertProfileKeyUsageTypeResource certProfileKeyUsageTypeService;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertProfileKeyUsageTypeResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    CommonUtil commonUtil;

    private final static int STATUS_OK = 200;

    KeyUsage keyUsage;
    List<KeyUsageType> keyUsageTypes;
    String jsonKeyUsageTypes;
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

        keyUsage = certificateProfileSetUpToTest.createKeyUsage();
        keyUsageTypes = certificateProfileSetUpToTest.createKeyUsage().getSupportedKeyUsageTypes();
        jsonKeyUsageTypes = mapper.writeValueAsString(keyUsageTypes);

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(certProfileKeyUsageTypeService);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching Key usage types in Certificate profile of given id
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException {

        Mockito.when(commonUtil.getCertificateExtension(1, KeyUsage.class)).thenReturn(keyUsage);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_USAGE_TYPE_MAPPER)).thenReturn(new ObjectMapper());

        request = MockHttpRequest.get("/certprofilekeyusagetype/fetch/1");

        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(jsonKeyUsageTypes, response.getContentAsString());
    }
}
