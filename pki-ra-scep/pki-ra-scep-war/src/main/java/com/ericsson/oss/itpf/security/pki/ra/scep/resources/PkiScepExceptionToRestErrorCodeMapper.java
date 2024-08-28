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
package com.ericsson.oss.itpf.security.pki.ra.scep.resources;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * ScepExceptionToRestErrorCodeMapper program maps all the internal and user defined exceptions to corresponding rest response error codes.
 *
 * @author xtelsow
 */
@Provider
public class PkiScepExceptionToRestErrorCodeMapper implements ExceptionMapper<Exception> {
    /**
     * This method maps the exception to corresponding error codes to rest response.
     *
     * @param exception
     *            internal or user defined exceptions
     *
     * @return Response appropriate response corresponding to exceptions
     */
    @Override
    public Response toResponse(Exception exception) {

        if (exception.getCause() != null) {
            exception = (Exception) exception.getCause();
        }
        Response.Status responseStatus = Response.Status.INTERNAL_SERVER_ERROR;
        if (exception instanceof BadRequestException) {
            responseStatus = Response.Status.BAD_REQUEST;
        } else if (exception instanceof NotImplementedException) {
            return Response.status(HttpServletResponse.SC_NOT_IMPLEMENTED).entity(exception.getMessage()).build();
        } else if (exception instanceof UnauthorizedException) {
            responseStatus = Response.Status.UNAUTHORIZED;
        }
        return Response.status(responseStatus).entity(exception.getMessage()).build();
    }
}
