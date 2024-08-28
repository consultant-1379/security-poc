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

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;
import javax.ws.rs.ext.Provider;

/**
 * CMPExceptionToRestErrorCodeMapper program maps all the internal and user defined exceptions to corresponding rest response error codes.
 *
 * @author xdeemin
 */
@Provider
public class TDPSExceptionMapper implements ExceptionMapper<Exception> {
    /**
     * This method maps the exception to corresponding error codes to send rest response
     *
     * @param exception
     *            internal or user defined exceptions
     *
     * @return Response appropriate response corresponding to exceptions
     */

    @Override
    public Response toResponse(final Exception exception) {

        Response.Status restStatus = Response.Status.INTERNAL_SERVER_ERROR;

        if (exception.getCause() != null) {
            switch (exception.getCause().getClass().getSimpleName()) {
            case "TrustDistributionPointURLNotFoundException":
                restStatus = Response.Status.NOT_FOUND;
                break;
            case "TrustDistributionServiceException":
            default:
                break;

            }
        } else {
            switch (exception.getClass().getSimpleName()) {
            case "IOException":
            case "MissingMandatoryParamException":
            case "InvalidTDPSCertificateStatusException":
            case "InvalidTDPSEntityException":
                restStatus = Response.Status.BAD_REQUEST;
                break;
            case "TrustDistributionPointURLNotFoundException":
                restStatus = Response.Status.NOT_FOUND;
                break;
            default:
                break;
            }
        }

        return Response.status(restStatus).entity(exception.getMessage()).build();

    }
}
