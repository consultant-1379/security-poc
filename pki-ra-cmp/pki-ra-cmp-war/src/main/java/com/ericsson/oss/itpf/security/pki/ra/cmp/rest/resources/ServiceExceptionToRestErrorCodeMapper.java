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


import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

/**
 * <p>
 * ServiceExceptionToRestErrorCodeMapper class maps all the Internal/User defined exceptions to appropriate HTTP Error Codes.
 * <p>
 * 
 * @author xdeemin
 */
@Provider
public class ServiceExceptionToRestErrorCodeMapper implements ExceptionMapper<Exception> {

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    Logger logger;
    /**
     * <p>
     * This method maps any exception which will be thrown from REST resource to appropriate error codes.Cause of the exception is taken into account and each exception class is mapped to appropriate
     * HTTP Error Code
     * <p>
     * for eg:In case there is any ProtocolException raised from EJB Service then it will be mapped to INTERNAL_SERVER_ERROR.
     *
     * @param exception
     *            Exception thrown from REST service
     *
     * @return Response appropriate response corresponding to exceptions
     */
    @Override
    public Response toResponse(final Exception exception) {
        Response.Status restStatus = null;

        Throwable throwable = null;
        if (exception.getCause() != null) {
            throwable = exception.getCause();
        } else {
            throwable = exception;
        }

        switch (throwable.getClass().getSimpleName()) {

        case "IOException":
        case "CertificateParsingException":
        case "InvalidCertificateVersionException":
        case "MessageParsingException":
        case "UnsupportedRequestTypeException":

            restStatus = Response.Status.BAD_REQUEST;
            break;

        case "ResponseBuilderException":
        default:
            restStatus = Response.Status.INTERNAL_SERVER_ERROR;
            break;

        }
        logger.error(throwable.getMessage());
        systemRecorder.recordError("CMP_SERVICE.SERVICE_FAILED", ErrorSeverity.ERROR, "CMP_SERVICE.CREDENTIAL_ISSUE_OR_REISSUE", "CMP_CLIENT", throwable.getClass().getSimpleName());

        return Response.status(restStatus).entity(throwable.getMessage()).build();
    }
}
