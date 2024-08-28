/*------------------------------------------------------------------------------
 *  *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.taf;

import java.io.IOException;

import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.fasterxml.jackson.core.JsonProcessingException;


@Path("/taf-entries")
public class DeleteTafDataResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @DELETE
    @Path("/entities/{entity_name}")
    public Response deleteTAFEndEntitiesFrmPKIManager(@PathParam("entity_name") final String entityNameSearchString) throws JsonProcessingException, IOException {
        logger.debug("Start deleting TAF End Entities from PKI Manager Database {}.", entityNameSearchString);

        final List<String> entityNames = pkiManagerEServiceProxy.getTafEntityManagementService().getEndEntityNamesFrmPKIManager(
                entityNameSearchString);

        for (final String entityName : entityNames) {
            pkiManagerEServiceProxy.getTafEntityManagementService().deleteEndEntityDataFrmPKIManager(entityName);
        }

        logger.debug("Successfully deleted TAF End Entities from PKI Manager Database");

        return Response.status(Status.OK).entity("Successfully deleted TAF End Entities from PKI Manager Database").build();
    }

    @DELETE
    @Path("/caentities/{caentity_name}")
    public Response deleteTAFCAEntitiesFrmPKIManager(@PathParam("caentity_name") final String caEntityNameSearchString) throws JsonProcessingException, IOException {
        logger.debug("Start deleting TAF CA Entities from PKI Manager Database {}.", caEntityNameSearchString);


        final List<String> caEntityNames = pkiManagerEServiceProxy.getTafEntityManagementService().getCAEntityNamesFrmPKIManager(
                caEntityNameSearchString);

        for (final String caEntityName : caEntityNames) {
            pkiManagerEServiceProxy.getTafEntityManagementService().deleteCAEntityDataFrmPKIManager(caEntityName);
        }

        logger.debug("Successfully deleted TAF CA Entities from PKI Manager Database");

        return Response.status(Status.OK).entity("Successfully deleted TAF CA Entities from PKI Manager TAF Database").build();
    }

    @DELETE
    @Path("/pki-core/entities/{entity_name}")
    public Response deleteTAFEndEntitiesFrmPKICore(@PathParam("entity_name") final String entityNameSearchString) throws JsonProcessingException, IOException {
        logger.debug("Start Deleting TAF End Entities from PKI Core Database {}.", entityNameSearchString);
        pkiManagerEServiceProxy.getTafEntityManagementService().deleteEndEntitiesFrmPKICore(entityNameSearchString);
        logger.debug("Successfully deleted TAF End Entities from PKI Core Database");
        return Response.status(Status.OK).entity("Successfully deleted TAF End Entities from PKI Core Database").build();
    }

    @DELETE
    @Path("/pki-core/caentities/{caentity_name}")
    public Response deleteTAFCAEntitiesFrmPKICore(@PathParam("caentity_name") final String caEntityNameSearchString) throws JsonProcessingException, IOException {
        logger.debug("Start deleting TAF CA Entities from PKI Core Database {}.", caEntityNameSearchString);


        final List<String> caEntityNames = pkiManagerEServiceProxy.getTafEntityManagementService().getCAEntityNamesFromPKICore(
                caEntityNameSearchString);

        for (final String caEntityName : caEntityNames) {

            pkiManagerEServiceProxy.getTafEntityManagementService().deleteCAEntityDataFromPKICore(caEntityName);
        }

        logger.debug("Successfully deleted TAF CA Entities from PKI Core Database");

        return Response.status(Status.OK).entity("Successfully deleted TAF CA Entities from PKI Core Database").build();
    }

    @DELETE
    @Path("/kaps/cakeys/{caentity_name}")
    public Response deleteTAFCAKeysFrmKaps(@PathParam("caentity_name") final String caentityNameSearchString) throws JsonProcessingException, IOException {
        logger.debug("Start Deleting TAF CA keys from kaps Database {}.", caentityNameSearchString);

        pkiManagerEServiceProxy.getTafEntityManagementService().deleteCaKeysFrmKaps(caentityNameSearchString);
        logger.debug("Successfully deleted TAF CA keys from kaps Database");

        return Response.status(Status.OK).entity("Successfully deleted TAF CA keys from kaps Database").build();
    }

    @DELETE
    @Path("/entitiesExtCA/{entity_name}")
    public Response deleteTAFExtCAEndEntitiesFrmPKIManager(@PathParam("entity_name") final String entityNameSearchString) throws JsonProcessingException, IOException {
        logger.debug("Start deleting TAF ExtCA End Entities from PKI Manager Database {}.", entityNameSearchString);

        final List<String> entityNames = pkiManagerEServiceProxy.getTafEntityManagementService().getEndEntityNamesFrmPKIManager(
                entityNameSearchString);

        for (final String entityName : entityNames) {
            pkiManagerEServiceProxy.getTafEntityManagementService().deleteExtCAEndEntityDataFrmPKIManager(entityName);
        }

        logger.debug("Successfully deleted TAF ExtCA End Entities from PKI Manager Database");

        return Response.status(Status.OK).entity("Successfully deleted TAF ExtCA End Entities from PKI Manager Database").build();
    }
}