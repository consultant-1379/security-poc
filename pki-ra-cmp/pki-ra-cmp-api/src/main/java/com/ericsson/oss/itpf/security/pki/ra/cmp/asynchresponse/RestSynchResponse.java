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
package com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse;
/**
 * This class includes an instance of AsynchronousResponse object 
 *
 */
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.jboss.resteasy.spi.AsynchronousResponse;

public class RestSynchResponse {

    private AsynchronousResponse asyncResponse;

    public AsynchronousResponse getAsyncResponse() {
        return asyncResponse;
    }

    public void setAsyncResponse(final AsynchronousResponse asynchResponse) {
        this.asyncResponse = asynchResponse;
    }

    public void send(final byte[] response) {
        this.asyncResponse.setResponse(Response.status(Status.OK).entity(response).build());
    }

}
