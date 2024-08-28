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
package com.ericsson.oss.itpf.security.rest.resources;

import java.security.NoSuchAlgorithmException;
import java.util.Properties;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.credmservice.api.CredMRestAvailability;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.ejb.startup.JcaFileResourceBean;
import com.ericsson.oss.itpf.security.credmservice.util.FileUtils;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

@Path("/1.0/cronCertificates")
@RequestScoped
public class CertCheck {

    @Inject
    private Logger logger;

    @EServiceRef
    private CredMService credMService;
    @Inject
    CredMRestAvailability credMPkiConfBean;

    @Inject
    private JcaFileResourceBean resourceBean;

    private static final String FILE_CERTS_PROPERTIES = "/ericsson/tor/data/credm/conf/credentialManagerConfigurator.properties";

    @GET
    @Path("/check")
    @Produces({ MediaType.APPLICATION_JSON })
    public Response checkPropertiesCronValues() {

        logger.info("(GET) checkCertificateValue");
        Response response = null;
        if (credMPkiConfBean.isEnabled()) {
            if (FileUtils.isExist(FILE_CERTS_PROPERTIES)) {
                final Properties property = PropertiesReader.getPropertiesFromFileSystem(FILE_CERTS_PROPERTIES);
                logger.info("Properties file contents: " + property.toString());
                response = Response.ok().entity(property).build();
            } else {
                logger.info("Properties file not found for cron enablers");
                response = Response.noContent().entity(FILE_CERTS_PROPERTIES + " file not found").build();
            }
        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return response;
    }

    @GET
    @Path("/remove")
    @Produces({ MediaType.APPLICATION_JSON })
    public Response removePropertiesCronValues() {

        logger.info("(GET) removeCertificateValue");
        Response response = null;
        if (credMPkiConfBean.isEnabled()) {
            if (FileUtils.isExist(FILE_CERTS_PROPERTIES)) {
                FileUtils.delete(FILE_CERTS_PROPERTIES);
                response = Response.ok().entity(FILE_CERTS_PROPERTIES + " file removed").build();
            } else {
                logger.info("Properties file not found for cron enablers");
                response = Response.noContent().entity(FILE_CERTS_PROPERTIES + " file not found").build();
            }
        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return response;
    }

    @GET
    @Path("/write")
    @Produces({ MediaType.APPLICATION_JSON })
    public Response writedefPropertiesCronValues() throws NoSuchAlgorithmException {

        logger.info("(GET) writePropertiesCronValues");
        Response response = null;
        if (credMPkiConfBean.isEnabled()) {
            if (FileUtils.isExist(FILE_CERTS_PROPERTIES)) {
                FileUtils.delete(FILE_CERTS_PROPERTIES);
            }
            resourceBean.init(FILE_CERTS_PROPERTIES);
            if (resourceBean.supportsWriteOperations()) {

                final StringBuilder rowString = new StringBuilder("checkCertsStatusOnTimeout=false\n");
                rowString.append("cronAllowed=false\n");
                rowString.append("forceCertificateRenewal=true\n");

                resourceBean.write(rowString.toString().getBytes(), false);

                response = Response.ok().entity(FILE_CERTS_PROPERTIES + " file written").build();
            }

        } else {
            logger.info("credMPkiConfBean is not yet enabled");
            response = Response.status(Status.SERVICE_UNAVAILABLE).entity("credMPkiConfBean is not yet enabled").build();
        }
        return response;
    }

}
