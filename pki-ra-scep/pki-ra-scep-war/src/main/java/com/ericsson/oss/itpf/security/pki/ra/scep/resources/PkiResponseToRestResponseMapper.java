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

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;

/**
 * PkiResponseToRestResponseMapper sends rest response with appropriate content type,status and message.
 *
 * @author xtelsow
 */
public class PkiResponseToRestResponseMapper {

    /**
     * This method builds the response based on values from pkisScepResponse.
     *
     * @param pkiScepResponse
     *            appropriate response after processing the PKI message.
     * @return Response appropriate response with restful status codes.
     */
    public Response toRestResponse(final PkiScepResponse pkiScepResponse) {
        final ResponseBuilder responseBuilder = Response.status(Response.Status.OK);
        return responseBuilder.type(pkiScepResponse.getContentType()).entity(pkiScepResponse.getMessage()).build();
    }

}
