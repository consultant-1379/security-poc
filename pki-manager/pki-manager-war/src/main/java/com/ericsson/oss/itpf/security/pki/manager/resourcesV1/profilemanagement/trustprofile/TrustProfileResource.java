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
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement.trustprofile;

import java.io.IOException;




import javax.ejb.EJB;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching, updating and saving a {@link TrustProfile}.
 * 
 * @author xhemgan
 * @version 1.2.4
 * 
 */
@Path("/1.0/trustprofile")
public class TrustProfileResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @EJB
    private ProfileManagementServiceLocal profileManagementServiceLocal;

    @Inject
    Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method loads the {@link TrustProfile} with given ID.
     * 
     * @param id
     *            ID of the trust profile to be fetched.
     * 
     * @return TrustProfile object with the given ID.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/load/{id}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response load(@PathParam("id") final long id) throws JsonProcessingException {

        logger.debug("Fetching trust profile with ID {}.", id);

        TrustProfile trustProfile = new TrustProfile();
        trustProfile.setId(id);

        trustProfile = pkiManagerEServiceProxy.getProfileManagementService().getProfile(trustProfile);

        final String result = getJsonForLoad(trustProfile);

        logger.debug("Successfully fetched trust profile. {}", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This methods creates the given {@link TrustProfile}
     * 
     * @param profile
     *            JSON string of the trust profile to be created.
     * 
     * @return TrustProfile object that is created.
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
    public Response save(final String profile) throws JsonProcessingException, IOException {

        logger.debug("Creating Trust profile {}.", profile);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_DESERIALIZER_MAPPER);

        TrustProfile trustProfile = mapper.readValue(profile, TrustProfile.class);

        trustProfile = pkiManagerEServiceProxy.getProfileManagementService().createProfile(trustProfile);

        final String result = getJsonForLoad(trustProfile);

        logger.debug("Successfully created trust profile {}.", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This methods updates the given {@link TrustProfile}
     * 
     * @param profile
     *            JSON string of the trust profile to be updated.
     * 
     * @return TrustProfile object that is updated.
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
    public Response update(final String profile) throws JsonProcessingException, IOException {

        logger.debug("Updating Trust profile {}.", profile);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_DESERIALIZER_MAPPER);

        TrustProfile trustProfile = mapper.readValue(profile, TrustProfile.class);

        trustProfile = pkiManagerEServiceProxy.getProfileManagementService().updateProfile(trustProfile);

        final String result = getJsonForLoad(trustProfile);

        logger.debug("Successfully updated trust profile {}.", result);

        return Response.status(Status.OK).entity(result).build();
    }

    /**
     * This method fetches ids and names of all active trust profiles.
     * 
     * @return a JSON Array containing active trust profiles.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching trust profiles.");

        final Profiles profiles = profileManagementServiceLocal.fetchActiveProfilesIdAndName(ProfileType.TRUST_PROFILE);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_ID_NAME_MAPPER);

        final String result = mapper.writeValueAsString(profiles.getTrustProfiles());

        logger.debug("Successfully fetched trust profiles. {}", result);

        return Response.status(Status.OK).entity(result).build();

    }

    private String getJsonForLoad(final TrustProfile trustProfile) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.TRUST_PROFILE_SERIALIZER_MAPPER);

        return mapper.writeValueAsString(trustProfile);
    }

}
