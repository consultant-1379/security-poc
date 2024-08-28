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

import java.net.URISyntaxException;

import org.jboss.resteasy.core.Dispatcher;
import org.jboss.resteasy.mock.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.EnumTypeSerializer;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Test class for {@link KeyPurposeIdResource}
 * 
 * @author xhemgan
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class KeyPurposeIdResourceTest {

    @InjectMocks
    KeyPurposeIdResource keyPurposeId;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Spy
    Logger logger = LoggerFactory.getLogger(KeyPurposeIdResource.class);

    private final static int STATUS_OK = 200;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    TestUtil testUtil;
    ObjectMapperUtilTest testObjectMapperUtil;

    /**
     * Method for setting up test data.
     */
    @Before
    public void setUp() throws Exception {

        testUtil = new TestUtil();
        testObjectMapperUtil = new ObjectMapperUtilTest();

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(keyPurposeId);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching {@link KeyPurposeId}
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException, JsonProcessingException {

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_PURPOSE_ID_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.KEY_PURPOSE_ID_MAPPER));

        request = MockHttpRequest.get("/1.0/keypurposeid/fetch");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(response.getContentAsString(), testUtil.getJsonForEnum(KeyPurposeId.class, new EnumTypeSerializer<KeyPurposeId>(), KeyPurposeId.values()));
    }
}
