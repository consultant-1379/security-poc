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
package com.ericsson.oss.itpf.security.pki.manager.rest.exceptionmapper;

import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.rest.util.CommonUtil;

/**
 * A mapper class to map {@link Exception} to {@link Response}
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Provider
public class PKIExceptionMapper implements ExceptionMapper<Exception> {

    @Inject
    private Logger logger;

    @Inject
    private CommonUtil commonUtil;

    /**
     * This method maps {@link Exception} to {@link Response}
     * 
     * @return a {@link Response} with error message in JSON comprising of ID and message.
     * 
     */
    @Override
    public Response toResponse(final Exception exception) {

        logger.error("An exception occurred while processing the request. {}", exception.getMessage());

        final String errorMessage = commonUtil.getJSONErrorMessage(exception.getMessage());

        return Response.status(Status.BAD_REQUEST).entity(errorMessage).build();
    }
}
