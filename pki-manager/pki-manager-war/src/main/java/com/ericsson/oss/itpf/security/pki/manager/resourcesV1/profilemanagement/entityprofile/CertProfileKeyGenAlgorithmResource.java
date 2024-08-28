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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.entityprofile;

import java.util.List;


import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * 
 * Rest service for fetching the key generation algorithms present in certificate profile.
 * 
 * @author tcspred
 * @version 1.1.30
 */
@Path("/1.0/certprofilekeygenalgorithm")
public class CertProfileKeyGenAlgorithmResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method lists the key generation algorithms in {@link CertificateProfile} of given ID .
     * 
     * @param certProfileId
     *            ID of the certificate profile from which list of key generation algorithms should be fetched.
     * 
     * @return a JSON Array containing key generation algorithms.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(@PathParam("id") final int certProfileId) throws JsonProcessingException {

        logger.debug("Fetching key generation algorithms from certificate profile with ID {}.", certProfileId);

        final List<Algorithm> keyGenerationAlgorithms = getKeyGenerationAlgorithms(certProfileId);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.KEY_GEN_ALGORITHM_SEIALIZER_MAPPER);

        final String result = mapper.writeValueAsString(keyGenerationAlgorithms);

        logger.debug("keyGenerationAlgorithms in Certificate profile fetched. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    private List<Algorithm> getKeyGenerationAlgorithms(final int id) {
        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(id);

        certificateProfile = pkiManagerEServiceProxy.getProfileManagementService().getProfile(certificateProfile);
        final List<Algorithm> keyGenerationAlgorithms = certificateProfile.getKeyGenerationAlgorithms();

        return keyGenerationAlgorithms;
    }
}
