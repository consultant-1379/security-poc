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
package com.ericsson.oss.itpf.security.pki.manager.resources.entitymanagement.caentity;

import java.io.IOException;




import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;



import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for loading, updating and saving a {@link CAEntity}.
 * 
 * @author tcspred
 * @version 1.1.30
 * 
 */
@Path("/caentity")
public class CAEntityResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method loads the {@link CAEntity} with given ID.
     * 
     * @param id
     *            ID of the CA entity to be fetched.
     * 
     * @return CAEntity object with the given ID.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/load/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(@PathParam("id") final int id) throws JsonProcessingException {

        logger.debug("Fetching CA entity with ID {}.", id);

        CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setId(id);
        caEntity.setCertificateAuthority(certificateAuthority);

        caEntity = pkiManagerEServiceProxy.getEntityManagementService().getEntity(caEntity);

        final String result = getJsonForLoad(caEntity);

        logger.debug("Successfully fetched CA entity. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This methods creates the given {@link CAEntity}
     * 
     * @param caEntityJSON
     *            JSON string of the CAEntity to be created.
     * 
     * @return CAEntity object that is created.
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
    public Response save(final String caEntityJSON) throws JsonProcessingException, IOException {

        logger.debug("Creating CA entity {}.", caEntityJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_DESERIALIZER_MAPPER);

        CAEntity caEntity = mapper.reader(CAEntity.class).readValue(caEntityJSON);

        caEntity = pkiManagerEServiceProxy.getEntityManagementService().createEntity(caEntity);

        final String result = getJsonForLoad(caEntity);

        logger.debug("Successfully created CA entity {}.", caEntity);

        return Response.status(Status.OK).entity(result).build();

    }

    /**
     * This methods updates the given {@link CAEntity}
     * 
     * @param caEntity
     *            JSON string of the CA entity to be updated.
     * 
     * @return CAEntity object that is updated.
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
    public Response update(final String caEntityJSON) throws JsonProcessingException, IOException {

        logger.debug("Updating CA entity {}.", caEntityJSON);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_DESERIALIZER_MAPPER);

        CAEntity caEntity = mapper.reader(CAEntity.class).readValue(caEntityJSON);

        caEntity = pkiManagerEServiceProxy.getEntityManagementService().updateEntity(caEntity);

        final String result = getJsonForLoad(caEntity);

        logger.debug("Successfully updated CA entity {}.", caEntity);

        return Response.status(Status.OK).entity(result).build();
    }

    private String getJsonForLoad(final CAEntity caEntity) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CA_ENTITY_FETCH_MAPPER);

        return mapper.writeValueAsString(caEntity);
    }
}
