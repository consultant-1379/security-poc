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
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.exception.*;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetTrustResponse;

@Path("/1.0/trust")
@RequestScoped
public class Trust {

    @Inject
    private Logger logger;

    @EServiceRef
    private CredMService credMService;

    @Inject
    CredMRestAvailability credMPkiConfBean;

    @GET
    @Path("/get")
    @Produces({ MediaType.APPLICATION_JSON })
    public Response getTrust() {
        this.logger.info("(GET) /1.0/trust called");
        Response response = null;
        if (this.credMPkiConfBean.isEnabled()) {

            try {
                CredentialManagerTrustMaps ca;
                ca = this.credMService.getTrustCertificates("credMServiceProfile");
                final GetTrustResponse caResp = new GetTrustResponse(ca);

                response = Response.ok().entity(caResp).build();
            } catch (final CredentialManagerInvalidArgumentException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInternalServiceException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerProfileNotFoundException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerCertificateEncodingException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInvalidProfileException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            }
        } else {
            this.logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return response;
    }
}
