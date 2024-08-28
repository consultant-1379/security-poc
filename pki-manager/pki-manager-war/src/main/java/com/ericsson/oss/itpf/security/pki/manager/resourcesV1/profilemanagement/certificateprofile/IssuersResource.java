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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.certificateprofile;

import java.util.List;


import javax.ejb.EJB;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.EntityManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching the issuers i.e, all the {@link CAEntity}.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/1.0/issuers")
public class IssuersResource {

    @EJB
    private EntityManagementServiceLocal entityManagementServiceLocal;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private Logger logger;

    /**
     * This method fetches all the {@link CAEntity}.
     * 
     * @return a JSON Array containing the issuers i.e., CA Entities.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching the Issuers.");

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ISSUER_ID_NAME_MAPPER);

        final List<CAEntity> caEntities = entityManagementServiceLocal.fetchCAEntitiesIdAndName(CAStatus.ACTIVE, false);

        final String result = mapper.writeValueAsString(caEntities);

        logger.debug("Issuers fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
