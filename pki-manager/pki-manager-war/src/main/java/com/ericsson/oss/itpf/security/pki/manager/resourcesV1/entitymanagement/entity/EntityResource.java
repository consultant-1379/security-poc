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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.entitymanagement.entity;

import java.io.IOException;



import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching, updating and saving a {@link Entity}.
 * 
 * @author tcspred
 * @version 1.1.30
 * 
 */
@Path("/1.0/entity")
public class EntityResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method loads the {@link Entity} with given ID.
     * 
     * @param id
     *            ID of the entity to be fetched.
     * 
     * @return Entity object with the given ID.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/load/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(@PathParam("id") final int id) throws JsonProcessingException {

        logger.debug("Fetching entity with ID {}.", id);

        Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setId(id);
        entity.setEntityInfo(entityInfo);

        entity = pkiManagerEServiceProxy.getEntityManagementService().getEntity(entity);

        final String result = getJsonForLoad(entity);

        logger.debug("Successfully fetched entity. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This methods creates the given {@link Entity}
     * 
     * @param entityJSON
     *            JSON string of the entity to be created.
     * 
     * @return Entity object that is created.
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
    public Response save(final String entityJSON) throws JsonProcessingException, IOException {

        logger.debug("Creating entity {}.", entityJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER);

        Entity entity = mapper.reader(Entity.class).readValue(entityJSON);

        entity = pkiManagerEServiceProxy.getEntityManagementService().createEntity(entity);

        final String result = getJsonForLoad(entity);

        logger.debug("Successfully created CA entity {}.", entity);

        return Response.status(Status.OK).entity(result).build();

    }

    /**
     * This methods updates the given {@link Entity}
     * 
     * @param entityJSON
     *            JSON string of the entity to be updated.
     * 
     * @return Entity object that is updated.
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
    public Response update(final String entityJSON) throws JsonProcessingException, IOException {

        logger.debug("Updating entity {}.", entityJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_DESERIALIZER_MAPPER);

        Entity entity = mapper.reader(Entity.class).readValue(entityJSON);

        entity = pkiManagerEServiceProxy.getEntityManagementService().updateEntity(entity);

        final String result = getJsonForLoad(entity);

        logger.debug("Successfully updated entity {}.", entity);

        return Response.status(Status.OK).entity(result).build();
    }

    private String getJsonForLoad(final Entity entity) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_FETCH_MAPPER);

        return mapper.writeValueAsString(entity);
    }
}
