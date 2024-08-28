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
package com.ericsson.oss.itpf.security.rest.resources;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;

@Path("/1.0/pib")
@RequestScoped
public class PibParameters {

    @Inject
    private Logger logger;

    @EServiceRef
    private CredMService credMService;

    @Inject
    CredMRestAvailability credMPkiConfBean;

    @GET
    @Path("/get")
    @Produces({ MediaType.APPLICATION_JSON })
    public Response getPib() {
        logger.info("(GET) /1.0/pib called");
        Response response = null;
        if (credMPkiConfBean.isEnabled()) {
                final CredentialManagerPIBParameters pib = credMService.getPibParameters();
                response = Response.ok().entity(pib).build();
        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return response;
    }
}
