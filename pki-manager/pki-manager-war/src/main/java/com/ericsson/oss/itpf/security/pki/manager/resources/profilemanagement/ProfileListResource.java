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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement;

import java.io.IOException;

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.AttributeType;
import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ProfileListDTO;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for deleting and fetching profiles.
 * 
 * @author xhemgan
 * @version 1.2.4
 * 
 */
@Path("/profilelist")
public class ProfileListResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private CommonUtil commonUtil;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    private final static String PROFILE_DELETED = "Profile deleted Successfully.";

    /**
     * This method deletes a profile based on the values set in {@link ProfileDeleteDTO}.
     * 
     * @param profileDeleteDTO
     *            Object containing ID and the type of profile to be deleted.
     * 
     * @return a message whether the profile has been deleted successfully or not.
     * @throws IOException
     * @throws JsonProcessingException
     */
    @DELETE
    @Path("/delete/{profiletype}/{id}")
    public Response delete(@PathParam("profiletype") final ProfileType profileType, @PathParam("id") final int id) throws JsonProcessingException, IOException {

        AbstractProfile profile = null;

        logger.debug("Deleting {} with ID {}.", profileType.getValue(), id);

        if (profileType == ProfileType.CERTIFICATE_PROFILE) {
            profile = new CertificateProfile();
        } else if (profileType == ProfileType.TRUST_PROFILE) {
            profile = new TrustProfile();
        } else if (profileType == ProfileType.ENTITY_PROFILE) {
            profile = new EntityProfile();
        } else {
            throw new IllegalArgumentException("Invalid Profile Type!");
        }

        profile.setId(id);

        pkiManagerEServiceProxy.getProfileManagementService().deleteProfile(profile);

        logger.debug("Successfully deleted {} with ID {}.", profileType.getValue(), id);

        return Response.status(Status.OK).entity(PROFILE_DELETED).build();
    }

    /**
     * This method fetches all the profiles and places the profile with ID set in {@link ProfileListDTO} in the first row.
     * 
     * @param profileListDTO
     *            Object containing ID of the profile that should be placed first in the result.
     * 
     * @return a JSON Array containing the profiles.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @POST
    @Path("/fetch")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch(final ProfileListDTO profileListDTO) throws JsonProcessingException {

        logger.debug("Fetching profiles.");

        final List<ProfileType> profileTypes = new ArrayList<ProfileType>();
        profileTypes.add(ProfileType.TRUST_PROFILE);
        profileTypes.add(ProfileType.CERTIFICATE_PROFILE);
        profileTypes.add(ProfileType.ENTITY_PROFILE);

        final Profiles profiles = pkiManagerEServiceProxy.getProfileManagementService().exportProfiles(profileTypes.toArray(new ProfileType[profileTypes.size()]));

        final String result = commonUtil.placeAttributeAtFirst(getProfilesInJson(profiles), AttributeType.ID, profileListDTO.getId());

        logger.debug("Successfully fetched the profiles.");

        return Response.status(Status.OK).entity(result).build();
    }

    private JSONArray getProfilesInJson(final Profiles profiles) throws JsonProcessingException {

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.CERTIFICATE_MAPPER);

        final JSONArray certProfilesArray = new JSONArray(mapper.writeValueAsString(profiles.getCertificateProfiles()));
        final JSONArray entityProfilesArray = new JSONArray(mapper.writeValueAsString(profiles.getEntityProfiles()));
        final JSONArray trustProfilesArray = new JSONArray(mapper.writeValueAsString(profiles.getTrustProfiles()));

        final JSONArray mergedArray = commonUtil.mergeJsonArray(certProfilesArray, entityProfilesArray, trustProfilesArray);

        return updateProfileTypeWithValue(mergedArray);
    }

    private JSONArray updateProfileTypeWithValue(final JSONArray mergedArray) {

        for (int i = 0; i < mergedArray.length(); i++) {
            final JSONObject jsonObject = mergedArray.getJSONObject(i);
            final String profileType = jsonObject.getString("type");
            final ProfileType profileTypeEnum = ProfileType.valueOf(profileType);
            jsonObject.put("profileType", profileTypeEnum.getValue());
            mergedArray.put(i, jsonObject);
        }

        return mergedArray;
    }

}
