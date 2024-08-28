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
package com.ericsson.oss.itpf.security.pki.ra.cmp.rest.resources;

import java.io.IOException;

import javax.security.cert.CertificateParsingException;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Response.class)
public class ServiceExceptionToRestErrorCodeMapperTest {

    @InjectMocks
    ServiceExceptionToRestErrorCodeMapper serviceExceptionToRestErrorCodeMapper;

    @Mock
    ResponseBuilder responseBuilder;

    @Mock
    SystemRecorder systemRecorder;
    
    @Mock
    Logger logger; 

    @Test
    public void testToResponse() {
        Exception exception = new IOException("Error");
        Status restStatus = Response.Status.BAD_REQUEST;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        serviceExceptionToRestErrorCodeMapper.toResponse(exception);

        Mockito.verify(logger).error(exception.getMessage()); 
        PowerMockito.verifyStatic();
        Response.status(restStatus);

    }

    @Test
    public void testToResponseBADREQUEST() {
        Exception exception = new IOException("CertificateParsingException");
        exception.initCause(new CertificateParsingException("CertificateParsingException"));
        Status restStatus = Response.Status.BAD_REQUEST;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        serviceExceptionToRestErrorCodeMapper.toResponse(exception);

        Mockito.verify(logger).error(exception.getMessage()); 
        PowerMockito.verifyStatic();
        Response.status(restStatus);

    }

    @Test
    public void testToResponseInternalServerError() {
        Exception exception = new IOException("ResponseBuilderException");
        exception.initCause(new ResponseBuilderException("ResponseBuilderException"));
        Status restStatus = Response.Status.INTERNAL_SERVER_ERROR;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        serviceExceptionToRestErrorCodeMapper.toResponse(exception);

        Mockito.verify(logger).error(exception.getMessage()); 
        PowerMockito.verifyStatic();
        Response.status(restStatus);

    }

}