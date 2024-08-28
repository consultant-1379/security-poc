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

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

/**
 * PkiResponseToRestResponseMapper sends rest response with appropriate content
 * type,status and message.
 *
 * @author xdeemin
 */
public class PKIResponseToRestResponseMapper {

    /**
     * This method builds success response.
     * 
     * @param pKISignedResponse
     *            appropriate response after processing the PKIMessage
     * @return Response response with restful status code of OK
     */
    public Response toRestResponse(final byte[] pKISignedResponse) {
        final ResponseBuilder responseBuilder = Response.status(Response.Status.OK);
        return responseBuilder.entity(pKISignedResponse).build();

    }

}
