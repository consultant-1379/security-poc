package com.ericsson.oss.services.scriptengine.rest.resources;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;

/**
 * Created by xsantmi on 8/8/2016.
 */
@Path("/")
public interface GrammarRestResource {

    /**
     * get all the deployed applications in grammar file
     * @return Response containing the json of deployed applications
     *
     */
    @GET
    @Path("/deployedApplications")
    @Produces(MediaType.APPLICATION_JSON)
    Response getDeployedApplicationsNameAsJSON();


    /**
     * get grammar rules for an application
     * @return Response containing the json of deployed applications
     *
     */
    @GET
    @Path("/grammar/{appName}")
    @Produces(MediaType.APPLICATION_JSON)
    Response readJSONForApplication(@PathParam("appName") final String applicationName ) throws IOException;

}
