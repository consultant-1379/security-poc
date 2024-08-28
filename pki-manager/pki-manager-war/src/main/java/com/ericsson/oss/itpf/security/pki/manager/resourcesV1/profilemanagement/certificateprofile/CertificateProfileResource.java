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

import java.io.IOException;


import javax.ejb.EJB;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching, updating and saving a {@link CertificateProfile}.
 * 
 * @author xhemgan
 * @version 1.1.30
 * 
 */
@Path("/1.0/certificateprofile")
public class CertificateProfileResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;


    @EJB
    private ProfileManagementServiceLocal profileManagementServiceLocal;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method loads the {@link CertificateProfile} with given ID.
     * 
     * @param id
     *            ID of the certificate profile to be fetched.
     * 
     * @return CertificateProfile object with the given ID.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/load/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(@PathParam("id") final int id) throws JsonProcessingException {

        logger.debug("Fetching certificate profile with ID {}.", id);

        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setId(id);

        certificateProfile = pkiManagerEServiceProxy.getProfileManagementService().getProfile(certificateProfile);

        final String result = getJsonForLoad(certificateProfile);

        logger.debug("Successfully fetched certificate profile. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This methods creates the given {@link CertificateProfile}
     * 
     * @param certProfile
     *            JSON string of the certificate profile to be created.
     * 
     * @return CertificateProfile object that is created.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @POST
    @Path("/save")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response save(final String certProfile) throws JsonProcessingException, IOException {

        logger.debug("Creating Certificate profile {}.", certProfile);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);

        CertificateProfile certificateProfile = mapper.reader(CertificateProfile.class).readValue(certProfile);

        certificateProfile = pkiManagerEServiceProxy.getProfileManagementService().createProfile(certificateProfile);

        final String result = getJsonForLoad(certificateProfile);

        logger.debug("Successfully created certificate profile {}.", certificateProfile);

        return Response.status(Status.OK).entity(result).build();

    }

    /**
     * This methods updates the given {@link CertificateProfile}
     * 
     * @param certProfile
     *            JSON string of the certificate profile to be updated.
     * 
     * @return CertificateProfile object that is updated.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     * @throws IOException
     *             thrown when any I/O errors occur.
     * 
     */
    @PUT
    @Path("/update")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response update(final String certProfile) throws JsonProcessingException, IOException {

        logger.debug("Updating Certificate profile {}.", certProfile);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.COMMON_MAPPER);

        CertificateProfile certificateProfile = mapper.reader(CertificateProfile.class).readValue(certProfile);

        certificateProfile = pkiManagerEServiceProxy.getProfileManagementService().updateProfile(certificateProfile);

        final String result = getJsonForLoad(certificateProfile);

        logger.debug("Successfully updated certificate profile {}.", certificateProfile);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This method fetches all active certificate profiles.
     * 
     * @return a JSON Array containing active certificate profiles.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching certificate profiles.");

        final Profiles profiles = profileManagementServiceLocal.fetchActiveProfilesIdAndName(ProfileType.CERTIFICATE_PROFILE);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_PROFILE_ID_NAME_MAPPER);

        final String result = mapper.writeValueAsString(profiles.getCertificateProfiles());

        logger.debug("Successfully fetched certificate profiles. {}", result);

        return Response.status(Status.OK).entity(result).build();

    }

    private String getJsonForLoad(final CertificateProfile certificateProfile) throws JsonProcessingException {

        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER);

        if (certificateProfile.getIssuer() != null) {
            certificateAuthority.setName(certificateProfile.getIssuer().getCertificateAuthority().getName());
            caEntity.setCertificateAuthority(certificateAuthority);
            certificateProfile.setIssuer(pkiManagerEServiceProxy.getEntityManagementService().getEntity(caEntity));
        }

        return mapper.writeValueAsString(certificateProfile);
    }
}