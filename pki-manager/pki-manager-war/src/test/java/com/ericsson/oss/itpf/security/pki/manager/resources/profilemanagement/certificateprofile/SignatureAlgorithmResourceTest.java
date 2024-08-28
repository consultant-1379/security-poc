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

import java.net.URISyntaxException;
import java.util.ArrayList;
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

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.configurationmanagement.api.PKIConfigurationManagementService;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.AlgorithmSetUpToTest;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Test class for {@link SignatureAlgorithmResource}
 * 
 * @author xhemgan
 * @version 1.1.30
 */
@RunWith(MockitoJUnitRunner.class)
public class SignatureAlgorithmResourceTest {

    @InjectMocks
    SignatureAlgorithmResource signatureAlgorithmService;

    @Spy
    Logger logger = LoggerFactory.getLogger(SignatureAlgorithmResource.class);

    @Mock
    PKIConfigurationManagementService pkiConfigurationManagementService;

    @Mock
    ObjectMapperUtil objectMapperUtil;

    @Mock
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    private final static int STATUS_OK = 200;

    Dispatcher dispatcher;

    MockHttpRequest request;
    MockHttpResponse response;

    List<Algorithm> algorithmsList = new ArrayList<Algorithm>();

    String jsonAlgorithms;

    /**
     * Method for setting up test data.
     */
    @Before
    public void setUp() throws Exception {
        final AlgorithmSetUpToTest algorithmSetUpToTest = new AlgorithmSetUpToTest();
        final ObjectMapper mapper = new ObjectMapper();

        algorithmsList.add(algorithmSetUpToTest.getSignatureAlgorithm());
        jsonAlgorithms = mapper.writeValueAsString(algorithmsList);
        Mockito.when(pkiManagerEServiceProxy.getPkiConfigurationManagementService()).thenReturn(pkiConfigurationManagementService); 

        dispatcher = MockDispatcherFactory.createDispatcher();
        dispatcher.getRegistry().addSingletonResource(signatureAlgorithmService);
        response = new MockHttpResponse();
    }

    /**
     * Method to test the rest service for fetching Signature Algorithms
     * 
     */
    @Test
    public void testFetch() throws URISyntaxException {

        Mockito.when(pkiConfigurationManagementService.getSupportedAlgorithmsByType(AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(algorithmsList);
        Mockito.when(objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER)).thenReturn(new ObjectMapper());

        request = MockHttpRequest.get("/signaturealgorithm/fetch");
        dispatcher.invoke(request, response);

        assertEquals(STATUS_OK, response.getStatus());
        assertEquals(jsonAlgorithms, response.getContentAsString());
    }
}
