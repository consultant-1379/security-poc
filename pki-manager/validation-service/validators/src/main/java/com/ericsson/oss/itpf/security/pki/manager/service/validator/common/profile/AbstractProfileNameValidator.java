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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Table;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;

/**
 * This class is used to validate name for all profiles.
 *
 *
 */
public abstract class AbstractProfileNameValidator {

    @Inject
    Logger logger;

    @Inject
    protected PersistenceManager persistenceManager;

    private static final String NAME_REGEX = "^[a-zA-Z0-9_ -]{3,255}$";

    public static final String TIME_PATTERN = "^(0*[1-9]+0*[1-9]*)\\s?(years|year|y|months|month|m|weeks|week|w|days|day|d|hours|hour|h)$";

    protected static final String VALIDITY_PATTERN = "^(?!^P0*Y0*M0*D)P([0-9]*Y)?([0-9]*M)?([0-9]*D)?$";

    protected static final String SKEW_VALIDITY_PATTERN = "^(?!^PT0*H0*M0*S)PT([0-9]*H)?([0-9]*M)?([0-9]*S)?$";

    /**
     * Method for verifying the profile name format
     *
     * @param profileName
     *            name to be checked
     */
    public void checkProfileNameFormat(final String profileName) throws InvalidProfileAttributeException {
        if (!ValidationUtils.validatePattern(NAME_REGEX, profileName)) {
            logger.debug(ProfileServiceErrorCodes.ERR_INVALID_NAME_FORMAT + " {}" , profileName);
            throw new InvalidProfileAttributeException(ProfileServiceErrorCodes.ERR_INVALID_NAME_FORMAT + " " + profileName);
        }

    }

    /**
     * Method for checking the availability of profile name
     *
     * @param profileName
     *            name to be checked
     * @param profileClass
     *            Class of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile}
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileAlreadyExistsException
     *             thrown when given profile already exists.
     */
    public <T> void checkProfileNameAvailability(final String profileName, final Class<T> profileClass) throws ProfileServiceException, ProfileAlreadyExistsException {
        try {
            if (!(persistenceManager.findEntityByName(profileClass, profileName, Constants.NAME_PATH) == null)) {
                final String profileclassdata = profileClass.getAnnotation(Table.class).name();
                logger.error("{} with name {} already exists", profileclassdata, profileName);
                throw new ProfileAlreadyExistsException(profileClass.getAnnotation(Table.class).name() + " with name " + profileName + " already exists");
            }
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error while checking database if name " + profileName + " exists in " + profileClass.getAnnotation(Table.class).name() , persistenceException);
            throw new ProfileServiceException("Error while checking database if name " + profileName + " exists in " + profileClass.getAnnotation(Table.class).name());
        }
    }

    /**
     * Method for retrieving the profile data from database
     *
     * @param id
     * @param profileDataClass
     * @return generic profile object which contains the data related to trust/entity/certificate profile
     * @throws ProfileNotFoundException
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when given {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile} doesn't exists in DB to update.
     */
    public <T> T getEntityData(final long id, final Class<T> profileDataClass) throws ProfileNotFoundException, ProfileServiceException {
        T profileData;
        try {
            profileData = persistenceManager.findEntity(profileDataClass, id);

        } catch (final PersistenceException persistenceException) {
            logger.debug("Error while checking database if id " + id + " exists in " + profileDataClass.getAnnotation(Table.class).name() , persistenceException);
            throw new ProfileServiceException("Error while checking database if id " + id + " exists in " + profileDataClass.getAnnotation(Table.class).name());
        }
        if (profileData == null) {
            logger.error(ProfileServiceErrorCodes.ERR_NO_PROFILE_FOUND + " with ID {}", id);
            throw new ProfileNotFoundException(ProfileServiceErrorCodes.ERR_NO_PROFILE_FOUND + " with ID " + id);
        }

        return profileData;
    }

    /**
     * Method for checking the profile name availability
     *
     * @param profileName
     *            Name to be checked
     * @param profileClass
     *            Class of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile}
     * @return <code>true</code> or <code>false</code>
     */
    public <T> boolean isNameAvailable(final String profileName, final Class<T> profileClass) throws ProfileServiceException {
        final String profileClassAnnotation = profileClass.getAnnotation(Table.class).name();
        logger.debug("availability of name {} in {}", profileName, profileClassAnnotation);

        boolean isProfileNameExists = false;

        try {
            if (persistenceManager.findEntityByName(profileClass, profileName, Constants.NAME_PATH) == null) {
                isProfileNameExists = true;
            }
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error in Checking DB! ", persistenceException);
            throw new ProfileServiceException(Constants.OCCURED_IN_VALIDATING);
        }

        return isProfileNameExists;
    }

    /**
     * Method for checking the profile name for updating the name
     *
     * @param givenName
     *            Name to be checked in update operation
     * @param actualName
     *            Actual name retrieved from DB.
     * @param profileClass
     *            Class of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile}
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileAlreadyExistsException
     *             thrown when given profile already exists.
     */
    public <T> void checkProfileNameForUpdate(final String givenName, final String actualName, final Class<T> profileClass) throws ProfileServiceException, ProfileAlreadyExistsException {

        if (!actualName.equals(givenName)) {
            checkProfileNameAvailability(givenName, profileClass);
        }
    }

    protected Class<? extends AbstractProfileData> getProfileDataClass(final ProfileType profileType) {
        switch (profileType) {
            case CERTIFICATE_PROFILE:
                return CertificateProfileData.class;
            case ENTITY_PROFILE:
                return EntityProfileData.class;
            case TRUST_PROFILE:
                return TrustProfileData.class;
            default:
                throw new IllegalArgumentException("Invalid Profile Type");
        }
    }
}
