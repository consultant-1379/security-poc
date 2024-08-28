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

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching the subject field types.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/subjectfieldtype")
public class SubjectFieldTypeResource {

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method lists the {@link SubjectFieldType}.
     * 
     * @return a JSON Array containing the SubjectFieldTypes and their IDs.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching the SubjectFieldTypes");

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_FIELD_TYPE_MAPPER);

        final String result = mapper.writeValueAsString(SubjectFieldType.values());

        logger.debug("SubjectFieldTypes fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
