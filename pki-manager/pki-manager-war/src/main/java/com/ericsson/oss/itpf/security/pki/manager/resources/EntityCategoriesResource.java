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
package com.ericsson.oss.itpf.security.pki.manager.resources;

import java.util.List;


import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching all available {@link EntityCategory} list from DB.
 * 
 * @author tcspred
 * @version 1.1.30
 * 
 */
@Path("/entitycategories")
public class EntityCategoriesResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method returns list of entity categories available in DB.
     * 
     * @return a JSON Array containing the supported entity categories.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching entity categories");

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_CATEGORY_MAPPER);

        final List<EntityCategory> entityCategories = pkiManagerEServiceProxy.getPkiConfigurationManagementService().listAllEntityCategories();

        final String result = mapper.writeValueAsString(entityCategories);

        logger.debug("Entity Categories fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
