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

import java.io.UnsupportedEncodingException;
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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.manager.rest.serializers.EnumTypeSerializer;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;

/**
 * Test class for {@link ReasonFlagsResource}
 * 
 * @author xhemgan
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class ReasonFlagsResourceTest {

    @InjectMocks
    ReasonFlagsResource reasonFlags;

    @Spy
    Logger logger = LoggerFactory.getLogger(ReasonFlagsResource.class);

    @Mock
    ObjectMapperUtil objectMapperUtil;

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
        dispatcher.getRegistry().addSingletonResource(reasonFlags);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching {@link ReasonFlag}
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException, UnsupportedEncodingException, JsonProcessingException {

        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.REASON_FLAGS_MAPPER)).thenReturn(testObjectMapperUtil.getObjectMapper(ObjectMapperType.REASON_FLAGS_MAPPER));

        request = MockHttpRequest.get("/reasonflags/fetch");
        dispatcher.invoke(request, response);

        assertEquals(response.getStatus(), STATUS_OK);
        assertEquals(response.getContentAsString(), testUtil.getJsonForEnum(ReasonFlag.class, new EnumTypeSerializer<ReasonFlag>(), ReasonFlag.values()));
    }
}
