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
package com.ericsson.oss.itpf.security.pki.cdps.exceptionmapper;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.MissingMandatoryParamException;

/**
 * CDPSExceptionToRestErrorCodeMapper program maps all the internal and user defined exceptions to corresponding rest response error codes.
 *
 * @author xjagcho
 */
@Provider
public class CDPSExceptionMapper implements ExceptionMapper<Exception> {
    @Inject
    private Logger logger;

    /**
     * This method maps the exception to corresponding error codes to rest response.
     *
     * @param exception
     *            internal or user defined exceptions
     *
     * @return Response appropriate response corresponding to exceptions
     */
    @Override
    public Response toResponse(final Exception exception) {
        logger.error("Exception occured related to " + exception.getMessage());

        Response.Status responseStatus = Response.Status.INTERNAL_SERVER_ERROR;
        Exception exceptionCause = exception;
        if (exception.getCause() != null) {
            exceptionCause = (Exception) exception.getCause();
        }
        if (exceptionCause instanceof MissingMandatoryParamException || exceptionCause instanceof CRLNotFoundException) {
            responseStatus = Response.Status.BAD_REQUEST;
        }

        return Response.status(responseStatus).entity(exceptionCause.getMessage()).build();
    }
}