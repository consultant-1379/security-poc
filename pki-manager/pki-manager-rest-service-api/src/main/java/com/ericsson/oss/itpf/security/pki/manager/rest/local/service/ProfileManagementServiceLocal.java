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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

/**
 * This interface is provided for handling the calls related to entity management
 * 
 * @author tcsgoma
 * 
 */
@EService
@Local
public interface ProfileManagementServiceLocal {

    /**
     * Returns count of Profiles that match with the given filter criteria.
     * 
     * @param profilesFilter
     *            specifies criteria based on which profiles have to be filtered
     * @return count of profiles matching given criteria
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    int getProfilesCountByFilter(ProfilesFilter profilesFilter) throws ProfileServiceException;

    /**
     * Returns list of Profiles that match with the given filter criteria and that lie between given offset, limit values.
     * 
     * @param ProfilesFilter
     *            specifies criteria, offset, limit values based on which Profiles have to be filtered
     * @return list of Profiles between given offset, limit values matching given criteria
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    List<AbstractProfile> getProfileDetails(ProfilesFilter profilesFilter) throws ProfileServiceException;

    /**
     * Get active profiles. It returns list of ids and names of active profiles of specified profile type.
     * 
     * @param profileType
     *            Profile Type specifies the type of profiles to be exported.It accepts values trustprofile, entityprofile, certificateprofile and all.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles or All.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    Profiles fetchActiveProfilesIdAndName(final ProfileType... profileTypes) throws ProfileServiceException;
}
