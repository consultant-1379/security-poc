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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.certificateprofile;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching the reason flags.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/reasonflags")
public class ReasonFlagsResource {

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method lists the {@link ReasonFlag}.
     * 
     * @return a JSON Array containing the ReasonFlags and their IDs.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching the ReasonFlags");

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.REASON_FLAGS_MAPPER);

        final String result = mapper.writeValueAsString(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag.values());

        logger.debug("ReasonFlags fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
