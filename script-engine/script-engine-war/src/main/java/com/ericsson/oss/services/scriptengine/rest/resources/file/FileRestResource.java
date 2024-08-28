/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.scriptengine.rest.resources.file;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

/**
 * Resource to support downloading files through script-engine.
 *
 * @since 1.6.2
 */
@Path("/")
public interface FileRestResource {


    /**
     * Download a file resource identified by the supplied file id.
     * @param applicationId identifies the application to which to route the request
     * @param fileId the application specific file id
     * @return Response containing the file to be downloaded. In case of an error an appropriate html error response is returned.
     */
    @GET
    @Produces(MediaType.APPLICATION_OCTET_STREAM)
    @Path("/files")
    Response downloadFile(@QueryParam("applicationId") final String applicationId, @QueryParam("fileId") final String fileId);

}