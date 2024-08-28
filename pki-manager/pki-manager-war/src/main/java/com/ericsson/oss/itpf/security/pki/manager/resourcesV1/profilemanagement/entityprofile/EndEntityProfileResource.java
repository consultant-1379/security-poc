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

import java.util.ArrayList;

import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.*;
import javax.ws.rs.core.Response.Status;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperType;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ObjectMapperUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Rest service for fetching {@link EntityProfile} related to entity.
 * 
 * @author tcspred
 * @version 1.1.30
 * 
 */
@Path("/1.0/endentityprofile")
public class EndEntityProfileResource {

    @Inject
    private PKIManagerEServiceProxy pkiManagerEServiceProxy;

    @Inject
    private Logger logger;

    @Inject
    private ObjectMapperUtil objectMapperUtil;

    /**
     * This method fetches id and names of all entity profiles related to entity.
     * 
     * @return a JSON Array containing list of entity profiles.
     * 
     * @throws JsonProcessingException
     *             thrown when any problem occurs while processing the JSON content.
     */
    @GET
    @Path("/fetch")
    @Produces(MediaType.APPLICATION_JSON)
    public Response fetch() throws JsonProcessingException {

        logger.debug("Fetching entity profiles related to entity.");

        final Profiles profiles = pkiManagerEServiceProxy.getProfileManagementService().exportProfiles(ProfileType.ENTITY_PROFILE);

        final List<EntityProfile> entityProfiles = getEntityProfilesForEntity(profiles);

        final ObjectMapper mapper = objectMapperUtil.getObjectMapper(ObjectMapperType.ENTITY_PROFILE_FETCH_MAPPER);

        final String result = mapper.writeValueAsString(entityProfiles);

        logger.debug("Successfully fetched entity profiles related to entity. {}", result);

        return Response.status(Status.OK).entity(result).build();

    }

    private List<EntityProfile> getEntityProfilesForEntity(final Profiles profiles) {
        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();

        for (final EntityProfile entityProfile : profiles.getEntityProfiles()) {

            if (!entityProfile.getCertificateProfile().isForCAEntity()) {
                entityProfiles.add(entityProfile);
            }
        }

        return entityProfiles;
    }
}
