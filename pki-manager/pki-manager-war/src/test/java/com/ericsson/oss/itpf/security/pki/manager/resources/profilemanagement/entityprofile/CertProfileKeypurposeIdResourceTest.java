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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup.CertificateProfileSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link CertProfileKeyPurposeIdResource}
 * 
 * @author tcspred
 * @version 1.2.4
 */
@RunWith(MockitoJUnitRunner.class)
public class CertProfileKeypurposeIdResourceTest {

    @InjectMocks
    CertProfileKeyPurposeIdResource certProfileKeyPurposeIdService;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertProfileKeyPurposeIdResource.class);

    @Mock
    ProfileManagementService profileManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    CommonUtil commonUtil;

    private final static int STATUS_OK = 200;

    ExtendedKeyUsage extendedKeyUsage;
    List<KeyPurposeId> keyPurposeIds;
    String jsonKeyPurposeIds;
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

        extendedKeyUsage = certificateProfileSetUpToTest.createExtendedKeyUsage();
        keyPurposeIds = certificateProfileSetUpToTest.createExtendedKeyUsage().getSupportedKeyPurposeIds();
        jsonKeyPurposeIds = mapper.writeValueAsString(keyPurposeIds);

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(certProfileKeyPurposeIdService);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching Key purpose ids in Certificate profile of given id
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException {

        Mockito.when(commonUtil.getCertificateExtension(1, ExtendedKeyUsage.class)).thenReturn(extendedKeyUsage);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.EXTENDED_KEY_USAGE_TYPE_MAPPER)).thenReturn(new ObjectMapper());

        request = MockHttpRequest.get("/certprofilekeypurposeid/fetch/1");

        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(jsonKeyPurposeIds, response.getContentAsString());
    }
}
