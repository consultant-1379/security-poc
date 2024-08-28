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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.persistence.handler.entity;

import java.math.BigInteger;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.ProfileModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfileFilterDynamicQueryBuilder;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

/**
 * This class is responsible for fetching both combinations of {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile} together using UNION operation. This class contains methods to
 * fetch the records by applying filter and without applying filter.
 * 
 * @author tcsgoma
 */
public class FilteredProfilesFetchHandler {
    @Inject
    PersistenceManager persistenceManager;

    @Inject
    ProfileModelMapperFactory profileModelMapperFactory;

    @Inject
    Logger logger;

    @Inject
    ProfileFilterDynamicQueryBuilder profileFilterDynamicQueryBuilder;

    /**
     * This method returns list of {@link CertificateProfile}/{@link EntityProfile}/{@link TrustProfile} that match with the given filter criteria and that lie between given offset, limit values.
     * 
     * @param profilesFilter
     *            ProfilesFilter object specifying criteria, offset, limit values based on which entities have to be filtered
     * @return list of profiles between given offset, limit values matching given criteria
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public List<AbstractProfile> getProfileDetails(final ProfilesFilter profilesFilter) throws ProfileServiceException {
        logger.debug("getProfileDetails by filter {} ", profilesFilter);
        List<Object[]> profileDetails = new ArrayList<Object[]>();
        final StringBuilder dynamicQuery = new StringBuilder();
        try {

            final Map<String, Object> attributes = profileFilterDynamicQueryBuilder.build(profilesFilter, dynamicQuery);
            logger.info("Union Query without filter is: {} " , dynamicQuery);
            profileDetails = persistenceManager.findEntitiesByNativeQuery(dynamicQuery.toString(), attributes, profilesFilter.getOffset(), profilesFilter.getLimit());

        } catch (final PersistenceException persistenceException) {
            logger.error("Unexpected Error in retrieving profiles that match with filtered criteria {}. {}", profilesFilter, persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + profilesFilter, persistenceException);
        }
        return mapProfiles(profileDetails);
    }

    private List<AbstractProfile> mapProfiles(final List<Object[]> profileDetails) {
        final List<AbstractProfile> profileDetailsList = new ArrayList<AbstractProfile>();
        for (final Object[] profileDetail : profileDetails) {
            switch ((String) profileDetail[4]) {
            case "CERTIFICATE_PROFILE": {
                final CertificateProfile certificateProfile = new CertificateProfile();
                certificateProfile.setId(((BigInteger) profileDetail[0]).longValue());
                certificateProfile.setName((String) profileDetail[1]);
                certificateProfile.setActive((Boolean) profileDetail[2]);
                profileDetailsList.add(certificateProfile);
                break;
            }
            case "ENTITY_PROFILE": {
                final EntityProfile entityProfile = new EntityProfile();
                entityProfile.setId(((BigInteger) profileDetail[0]).longValue());
                entityProfile.setName((String) profileDetail[1]);
                entityProfile.setActive((Boolean) profileDetail[2]);
                profileDetailsList.add(entityProfile);
                break;
            }
            case "TRUST_PROFILE": {
                final TrustProfile trustProfile = new TrustProfile();
                trustProfile.setId(((BigInteger) profileDetail[0]).longValue());
                trustProfile.setName((String) profileDetail[1]);
                trustProfile.setActive((Boolean) profileDetail[2]);
                profileDetailsList.add(trustProfile);
                break;
            }
            }

        }

        return profileDetailsList;
    }

}