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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler;

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.junit.Assert.assertThat;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.ResponseHandlerException;

@RunWith(MockitoJUnitRunner.class)
public class ResponseHandlerFactoryImplTest {

    @InjectMocks
    ResponseHandlerFactoryImpl cmpResponseHandlerFactoryImpl;

    @Mock
    ResponseHandler responseHandler;

    @Mock
    InitializationResponseHandler initializationResponseHandler;

    @Mock
    KeyUpdateResponseHandler keyUpdateResponseHandler;

    CMPResponse cMPResponse = new CMPResponse();

    @Test
    public void testGetResponseHandlerForIP() {
        responseHandler = cmpResponseHandlerFactoryImpl.getResponseHandler(cMPResponse);
        assertThat(responseHandler, instanceOf(InitializationResponseHandler.class));
    }

    @Test
    public void testGetResponseHandlerForKUP() {
        cMPResponse.setResponseType(1);
        responseHandler = cmpResponseHandlerFactoryImpl.getResponseHandler(cMPResponse);
        assertThat(responseHandler, instanceOf(KeyUpdateResponseHandler.class));
    }

    @Test
    public void testGetResponseHandlerForCmpError() {

        responseHandler = cmpResponseHandlerFactoryImpl.getResponseHandler(cMPResponse);
        assertThat(responseHandler, instanceOf(ResponseHandler.class));
    }

    @Test(expected = ResponseHandlerException.class)
    public void testGetResponseHandlerForUnknownError() {

        cMPResponse.setResponseType(19);
        cmpResponseHandlerFactoryImpl.getResponseHandler(cMPResponse);

    }
}