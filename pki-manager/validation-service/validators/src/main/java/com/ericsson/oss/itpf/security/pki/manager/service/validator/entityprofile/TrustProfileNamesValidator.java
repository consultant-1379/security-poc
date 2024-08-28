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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;

/**
 * This class validates trustprofile present in {@link EntityProfile}.
 *
 * @author tcsvmeg
 *
 */
public class TrustProfileNamesValidator implements CommonValidator<EntityProfile> {

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Inject
    Logger logger;

    @Inject
    CommonProfileHelper commonProfileHelper;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.validation.common.CommonValidator #validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        validateTrustProfiles(entityProfile);
    }

    private void validateTrustProfiles(final EntityProfile entityProfile) throws ProfileServiceException, ProfileNotFoundException {
        logger.trace("Checking if Trust Profiles exist in DB ");

        final List<TrustProfile> trustProfiles = entityProfile.getTrustProfiles();

        if (ValidationUtils.isNullOrEmpty(trustProfiles)) {
            return;
        }

        final ProfilePersistenceHandler<TrustProfile> trustProfilePersistenceHandler = commonProfileHelper.getPersistenceHandler(ProfileType.TRUST_PROFILE);

        for (final TrustProfile givenTrustProfile : trustProfiles) {
            final String trustProfileName = givenTrustProfile.getName();

            TrustProfile trustProfile = new TrustProfile();
            trustProfile.setName(trustProfileName);

            trustProfile = trustProfilePersistenceHandler.getProfile(trustProfile);

            if (trustProfile == null) {
                logger.error("{} Does not exists !!", trustProfileName);
                throw new ProfileNotFoundException(ProfileServiceErrorCodes.ERR_NO_TRUSTPROFILE_NAME_FOUND + trustProfileName);
            }
        }
    }
}
