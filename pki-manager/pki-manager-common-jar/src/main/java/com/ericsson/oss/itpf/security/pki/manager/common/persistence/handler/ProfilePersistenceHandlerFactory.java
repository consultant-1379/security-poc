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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * Persistence Handler Factory used to get the instance of proper Profile Persistence handler out of {@link EntityProfile}/{@link CertificateProfile}/ {@link TrustProfile}/
 * {@link CAEntityPersistenceHandler} / {@link EntityPersistenceHandler} persistence handlers.
 * 
 */
public class ProfilePersistenceHandlerFactory {
    @Inject
    @ProfileQualifier(ProfileType.TRUST_PROFILE)
    ProfilePersistenceHandler<TrustProfile> trustProfilePersistenceHandler;

    @Inject
    @ProfileQualifier(ProfileType.ENTITY_PROFILE)
    ProfilePersistenceHandler<EntityProfile> entityProfilePersistenceHandler;

    @Inject
    @ProfileQualifier(ProfileType.CERTIFICATE_PROFILE)
    ProfilePersistenceHandler<CertificateProfile> certificateProfilePersistenceHandler;

    /**
     * The method to get the appropriate {@link ProfilePersistenceHandler} instance based on {@link ProfileType}.
     * 
     * @param profileType
     * @return Instance of {@link ProfilePersistenceHandler}
     */
    public ProfilePersistenceHandler<? extends AbstractProfile> getProfilePersistenceHandler(final ProfileType profileType) throws InvalidProfileException {

        ProfilePersistenceHandler<? extends AbstractProfile> profilePersistenceHandler = null;

        switch (profileType) {

        case TRUST_PROFILE:
            profilePersistenceHandler = trustProfilePersistenceHandler;
            break;

        case ENTITY_PROFILE:
            profilePersistenceHandler = entityProfilePersistenceHandler;
            break;

        case CERTIFICATE_PROFILE:
            profilePersistenceHandler = certificateProfilePersistenceHandler;
            break;

        default:
            throw new InvalidProfileException(ProfileServiceErrorCodes.ERR_INVALID_PROFILE_TYPE);
        }
        return profilePersistenceHandler;
    }

}
