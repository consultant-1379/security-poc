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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.ProfileManager;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.ProfileManagementServiceLocal;

/**
 * This class implements {@link ProfileManagementServiceLocal} for handling the calls related to profile management
 * 
 * @author tcsgoma
 * 
 */
@Profiled
@Stateless
public class ProfileManagementServiceLocalBean implements ProfileManagementServiceLocal {

    @Inject
    private ProfileManager profileManager;

    @Inject
    private Logger logger;

    /**
     * This method returns count of {@link CertificateProfile}/{@link EntityProfile}/{@link TrustProfile} that match with the given filter criteria
     * 
     * @param profilesFilter
     *            ProfilesFilter object specifying criteria based on which entities have to be filtered
     * @return integer count of entities matching given criteria
     * @throws ProfileServiceException
     */
    @Override
    // TODO : TORF-109271 - RBAC: Align to latest Security SDK and remove deprecated annotations
    @Authorize(action = "read", resource = "read_profiles", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public int getProfilesCountByFilter(final ProfilesFilter profilesFilter) throws ProfileServiceException {
        logger.debug("get count of Entities that match the given filter dto {} ", profilesFilter);

        final int count = profileManager.getProfilesCountByFilter(profilesFilter);

        logger.debug("Retrieved count of Entities that match with the given filter criteria");

        return count;
    }

    /**
     * This method returns list of combinations of {@link CertificateProfile}/{@link EntityProfile}/{@link TrustProfile} that match with the given filter criteria and that lie between given offset,
     * limit values.
     * 
     * @param profilesFilter
     *            ProfilesFilter object specifying criteria, offset, limit values based on which profiles have to be filtered
     * @return list of profiles between given offset, limit values matching given criteria
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    // TODO : TORF-109271 - RBAC: Align to latest Security SDK and remove deprecated annotations
    @Authorize(action = "read", resource = "read_profiles", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public List<AbstractProfile> getProfileDetails(final ProfilesFilter profilesFilter) throws ProfileServiceException {
        logger.debug("getProfileDetails by filter {} ", profilesFilter);

        final List<AbstractProfile> profilesList = profileManager.getProfileDetails(profilesFilter);

        logger.debug("Retrieved Profiles between given offset, limit values that match with given filter criteria");

        return profilesList;
    }

    /**
     * This method returns all active profiles of specified type in Profiles Object.
     * 
     * @param profileType
     *            Profile Type specifies the type of profiles to be exported.It accepts values trustprofile, entityprofile, certificateprofile and all.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles or All.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    @Authorize(action = "read", resource = "read_profiles", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public Profiles fetchActiveProfilesIdAndName(final ProfileType... profileTypes) throws ProfileServiceException {
        logger.debug("fetch id and name of profiles of profile type {} ", profileTypes);

        if (profileTypes.length == 0) {
            throw new IllegalArgumentException(ProfileServiceErrorCodes.NO_PROFILETYPE_PRESENT);
        }

        final Profiles profiles = profileManager.getActiveProfiles(profileTypes, false);

        logger.debug("Retrieved ids and names of active profiles of type {}", profileTypes);

        return profiles;
    }

}
