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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching the subjectaltname field types.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/1.0/subjectaltnamefieldtype")
public class SubjectAltNameFieldTypeResource {

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method lists the {@link com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType} .
     * 
     * @return a JSON Array containing the SubjectAltNameFieldTypes and their IDs.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching the SubjectAltNameFieldTypes");

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.SUBJECT_ALT_NAME_TYPE_MAPPER);

        final String result = mapper.writeValueAsString(com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType.values());

        logger.debug("SubjectAltNameFieldTypes fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }
}
