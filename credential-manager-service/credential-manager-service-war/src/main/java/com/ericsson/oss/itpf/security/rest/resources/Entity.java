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
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.CreateAndGetEndEntityRequest;

@Path("/1.0/entity")
@RequestScoped
public class Entity {

    @Inject
    private Logger logger;

    @EServiceRef
    private CredMService credMService;

    @Inject
    CredMRestAvailability credMPkiConfBean;

    @POST
    @Path("/create")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces({ MediaType.APPLICATION_JSON })
    public Response createAndGetEndEntity(final CreateAndGetEndEntityRequest entityRequest) {
        logger.info("(POST) createEntity called");
        Response response = null;
        if (credMPkiConfBean.isEnabled()) {
			try{
            	final String endEntityProfileName = "credMServiceProfile";

                final CredentialManagerProfileInfo profile = credMService.getProfile(endEntityProfileName);

                final CredentialManagerSubject subject = profile.getSubjectByProfile();
                subject.setCommonName(entityRequest.getHostname().replace("CN=", ""));

                final CredentialManagerSubjectAltName subjectAltName = profile.getSubjectDefaultAlternativeName();
                final CredentialManagerAlgorithm keyGenerationAlgorithm = profile.getKeyPairAlgorithm();

                final CredentialManagerEntity getEndEntityResponse = credMService.createAndGetEntity(entityRequest.getHostname(), subject,
                        subjectAltName, keyGenerationAlgorithm, endEntityProfileName);

                response = Response.ok().entity(getEndEntityResponse).build();
            } catch (final CredentialManagerInvalidArgumentException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInternalServiceException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerProfileNotFoundException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInvalidProfileException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            } catch (final CredentialManagerInvalidEntityException e) {
                response = Response.serverError().entity(e.getMessage()).build();
            }
        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }

        return response;
    }
}
