/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.resourcesV2.entitymanagement.entity;

import java.io.IOException;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for updating and saving a {@link Entity}.
 * 
 * @author zganram
 *
 */
@Path("/v2/entity")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class EntityResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method creates the given {@link Entity}
     * 
     * @param entityJSON
     *            JSON string of the entity to be created.
     * 
     * @return Entity object that is created.
     * 
     * @throws IOException
     *             thrown when any I/O errors occur.
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @POST
    @Path("/save")
    public Response save(final String entityJSON) throws IOException, JsonProcessingException {

        logger.debug("Creating entity {}.", entityJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER);

        Entity entity = mapper.reader(Entity.class).readValue(entityJSON);

        entity = pkiManagerEServiceProxy.getEntityManagementService().createEntity_v1(entity);

        final String result = getJsonForLoad(entity);

        logger.debug("Successfully created entity {}.", entity);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This method updates the given {@link Entity}
     * 
     * @param entityJSON
     *            JSON string of the entity to be updated.
     * 
     * @return Entity object that is updated.
     * 
     * @throws IOException
     *             thrown when any I/O errors occur.
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * 
     */
    @PUT
    @Path("/update")
    public Response update(final String entityJSON) throws IOException, JsonProcessingException {

        logger.debug("Updating entity {}.", entityJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER);

        Entity entity = mapper.reader(Entity.class).readValue(entityJSON);

        entity = pkiManagerEServiceProxy.getEntityManagementService().updateEntity_v1(entity);

        final String result = getJsonForLoad(entity);

        logger.debug("Successfully updated entity {}.", entity);

        return Response.status(Status.OK).entity(result).build();
    }

    private String getJsonForLoad(final Entity entity) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_FETCH_MAPPER);

        return mapper.writeValueAsString(entity);
    }
}
