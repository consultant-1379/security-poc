/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.resourcesV1.profilemanagement;

import java.util.ArrayList;

import java.util.List;

import javax.ejb.EJB;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.json.JSONArray;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.adapter.ProfilesFilterAdapter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfileFilterDTO;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.ProfilesDTO;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.dto.validators.DTOValidator;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching list of {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile} objects.
 *
 * @author tcsgoma
 * @version
 *
 */
@Path("/1.0/profiles")
public class ProfilesResource {

    @EJB
    private ProfileManagementServiceLocal profileManagementServiceLocal;

    @Inject
    private DTOValidator dtoValidator;

    @Inject
    private ProfilesFilterAdapter profilesFilterAdapter;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    @Inject
    private Logger logger;

    /**
     * This method returns the count of profiles that match with {@link ProfileFilterDTO}.
     *
     * @param profilefilterDTO
     *            ProfileFilterDTO object containing filter conditions based on which profile has to be filtered.
     *
     * @return count number of profiles that match with given filter criteria
     * @throws JsonProcessingException
     */
    @POST
    @Path("/count")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response count(final ProfileFilterDTO profilefilterDTO) throws JsonProcessingException {
        int count = 0;

        logger.debug("Retrieving count of profiles that match with given filter criteria {}.", profilefilterDTO);

        final boolean isProfileFilterDTOValid = dtoValidator.validateProfileFilterDTO(profilefilterDTO);

        if (!isProfileFilterDTOValid) {
            return Response.status(Status.OK).entity(count).build();
        }

        final ProfilesFilter profilesFilter = profilesFilterAdapter.toProfilesFilter(profilefilterDTO);

        count = profileManagementServiceLocal.getProfilesCountByFilter(profilesFilter);

        logger.debug("Successfully retrieved profiles count {} matching with filterDTO {}.", count, profilefilterDTO);

        return Response.status(Status.OK).entity(count).build();
    }

    /**
     * This method returns list of Profiles that match with the given filter criteria, that lie between given offset, limit values.
     *
     * @param profilesDTO
     *            specifies criteria, offset, limit values based on which profiles have to be filtered.
     *
     * @return a JSON Array containing the profiles.
     *
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(final ProfilesDTO profilesDTO) throws JsonProcessingException {
        logger.debug("Fetching profiles.");

        final boolean isProfilesDTOValid = dtoValidator.validateProfilesDTO(profilesDTO);

        if (!isProfilesDTOValid) {
            final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.PROFILES_FETCH_MAPPER);
            final String result = mapper.writeValueAsString(new ArrayList<AbstractProfile>());

            return Response.status(Status.OK).entity(result).build();
        }

        final ProfilesFilter profilesFilter = profilesFilterAdapter.toProfilesFilter(profilesDTO);

        String result = null;

        final List<AbstractProfile> profileDetails = profileManagementServiceLocal.getProfileDetails(profilesFilter);

        result = getProfileDetailsInJson(profileDetails).toString();

        logger.debug("Successfully fetched the profiles.");

        return Response.status(Status.OK).entity(result).build();
    }

    private JSONArray getProfileDetailsInJson(final List<AbstractProfile> profileDetails) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.PROFILES_FETCH_MAPPER);

        final JSONArray profileDetailsArray = new JSONArray(mapper.writeValueAsString(profileDetails));

        return profileDetailsArray;

    }

}