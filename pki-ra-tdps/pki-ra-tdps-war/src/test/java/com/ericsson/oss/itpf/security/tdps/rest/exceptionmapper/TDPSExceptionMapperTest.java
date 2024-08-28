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
package com.ericsson.oss.itpf.security.tdps.rest.exceptionmapper;

import java.io.IOException;

import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.ResponseBuilder;
import javax.ws.rs.core.Response.Status;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Response.class)	
public class TDPSExceptionMapperTest {

    @InjectMocks
    TDPSExceptionMapper tdpsExceptionMapper;

    @Mock
    ResponseBuilder responseBuilder;

    @Test
    public void testToResponse() {
        Exception exception = new IOException();

        Status restStatus = Response.Status.BAD_REQUEST;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        tdpsExceptionMapper.toResponse(exception);

        PowerMockito.verifyStatic(Response.class);
        Response.status(restStatus);
    }

    @Test
    public void testToResponseDefault() {
        Exception exception = new IOException();

        exception.initCause(new TrustDistributionPointURLNotFoundException());

        Status restStatus = Response.Status.NOT_FOUND;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        tdpsExceptionMapper.toResponse(exception);

        PowerMockito.verifyStatic(Response.class);
        Response.status(restStatus);

    }

    @Test
    public void testToResponseNotNull() {
        Exception exception = new IOException();
        exception.initCause(new TrustDistributionServiceException());
        Status restStatus = Response.Status.INTERNAL_SERVER_ERROR;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        tdpsExceptionMapper.toResponse(exception);

        PowerMockito.verifyStatic(Response.class);
        Response.status(restStatus);

    }

    @Test
    public void testToResponseNotNullURLNotFoundExc() {
        Exception exception = new IOException();
        exception.initCause(new TrustDistributionPointURLNotFoundException());

        Status restStatus = Response.Status.NOT_FOUND;
        PowerMockito.mockStatic(Response.class);
        BDDMockito.given(Response.status(restStatus)).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.entity(exception.getMessage())).willReturn(responseBuilder);
        BDDMockito.given(responseBuilder.build()).willReturn(null);

        tdpsExceptionMapper.toResponse(exception);

        PowerMockito.verifyStatic(Response.class);
        Response.status(restStatus);

    }

}
