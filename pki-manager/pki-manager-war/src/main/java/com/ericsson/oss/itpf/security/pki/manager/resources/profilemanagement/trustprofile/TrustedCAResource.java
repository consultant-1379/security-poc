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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.trustprofile;

import java.util.ArrayList;

import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching trusted CAs.
 * 
 * @author xhemgan
 * @version 1.2.4
 * 
 */
@Path("/trustedCA")
public class TrustedCAResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private Logger logger;

    /**
     * This method fetches all the {@link CAEntity}.
     * 
     * @return a JSON Array containing the trusted CAs i.e., CA Entities.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching the Trusted CAs.");

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.TRUSTED_CA_MAPPER);
        final List<EntityType> entityTypes = new ArrayList<EntityType>();

        entityTypes.add(EntityType.CA_ENTITY);

        final Entities entities = pkiManagerEServiceProxy.getEntityManagementService().getEntities(entityTypes.toArray(new EntityType[entityTypes.size()]));

        final String result = mapper.writeValueAsString(entities.getCAEntities());

        logger.debug("Trusted CAs fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
