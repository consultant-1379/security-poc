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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.entityprofile;

import java.io.IOException;


import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching, updating and saving a {@link EntityProfile}.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/1.0/entityprofile")
public class EntityProfileResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method loads the {@link EntityProfile} with given ID.
     * 
     * @param id
     *            ID of the entity profile to be fetched.
     * 
     * @return EntityProfile object with the given ID.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/load/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(@PathParam("id") final int id) throws JsonProcessingException {

        logger.debug("Fetching entity profile with ID {}.", id);

        EntityProfile entityProfile = new EntityProfile();
        entityProfile.setId(id);

        entityProfile = pkiManagerEServiceProxy.getProfileManagementService().getProfile(entityProfile);

        final String result = getJsonForLoad(entityProfile);

        logger.debug("Successfully fetched entity profile. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This methods creates the given {@link EntityProfile}
     * 
     * @param entityProfileJSON
     *            JSON string of the entity profile to be created.
     * 
     * @return EntityProfile object that is created.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @POST
    @Path("/save")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response save(final String entityProfileJSON) throws JsonProcessingException, IOException {

        logger.debug("Creating entity profile {}.", entityProfileJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);

        EntityProfile entityProfile = mapper.reader(EntityProfile.class).readValue(entityProfileJSON);

        entityProfile = pkiManagerEServiceProxy.getProfileManagementService().createProfile(entityProfile);

        final String result = getJsonForLoad(entityProfile);

        logger.debug("Successfully created entity profile {}.", entityProfile);

        return Response.status(Status.OK).entity(result).build();

    }

    /**
     * This methods updates the given {@link EntityProfile}
     * 
     * @param entityProfileJSON
     *            JSON string of the certificate profile to be updated.
     * 
     * @return EntityProfile object that is updated.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @PUT
    @Path("/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response update(final String entityProfileJSON) throws JsonProcessingException, IOException {

        logger.debug("Updating entity profile {}.", entityProfileJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);

        EntityProfile entityProfile = mapper.reader(EntityProfile.class).readValue(entityProfileJSON);

        entityProfile = pkiManagerEServiceProxy.getProfileManagementService().updateProfile(entityProfile);

        final String result = getJsonForLoad(entityProfile);

        logger.debug("Successfully updated entity profile {}.", entityProfile);

        return Response.status(Status.OK).entity(result).build();
    }

    private String getJsonForLoad(final EntityProfile entityProfile) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_MAPPER);

        return mapper.writeValueAsString(entityProfile);
    }
}
