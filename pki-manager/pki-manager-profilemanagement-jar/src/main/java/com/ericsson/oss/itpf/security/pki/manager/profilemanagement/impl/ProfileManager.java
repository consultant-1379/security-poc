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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.persistence.handler.entity.FilteredProfilesFetchHandler;

/**
 * This abstract class contains common methods that are used by all profile managers. This class is extended by all profile managers.
 */
public class ProfileManager {

    @Inject
    Logger logger;

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Inject
    FilteredProfilesFetchHandler filteredProfilesFetchHandler;

    private static final int DEFAULT_PROFILE_ID = 0;

    /**
     * API for creating a {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile}.
     * 
     * @param profile
     *            {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} instance that is to be created.
     * @return Instance of Created {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile}
     * 
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T extends AbstractProfile> T createProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        logger.debug("creating {} with Name: {}", profile.getType(), profile.getName());

        profile.setId(DEFAULT_PROFILE_ID);

        final ProfilePersistenceHandler<T> profilePersistenceHandler = (ProfilePersistenceHandler<T>) getProfilePersistenceHandler(profile.getType());
        profile = profilePersistenceHandler.createProfile(profile);

        logger.info("{} created with ID: {}", profile.getType(), profile.getId());

        return profile;
    }

    /**
     * API for retrieving {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile}
     * 
     * @param profileTypes
     *            ProfileType specifies the type of profiles to be exported.It accepts Variable argument values namely CertificateProfile, TrustProfile, EntityProfile.
     * @return Instance of {@link Profiles} containing list of {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} instances
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public Profiles getProfiles(final ProfileType... profileTypes) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {

        logger.debug("Retrieving all profiles of Type: {}", new Object[] { profileTypes });

        final List<ProfileType> profileTypeList = Arrays.asList(profileTypes);
        final Profiles pkiProfiles = getProfilesByType(profileTypeList);

        logger.debug("{}s Retrieved", pkiProfiles);

        return pkiProfiles;
    }

    /**
     * API for retrieving the {@link TrustProfile} based on Id/Name.
     * 
     * @param profile
     *            instance {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} with Id/name set.
     * @return instance of {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} found in DB.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileNotFoundException
     *             thrown when profile do not exists in DB.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws MissingMandatoryFieldException
     *             thrown when the provided input is invalid.
     */
    public <T extends AbstractProfile> T getProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException,
            MissingMandatoryFieldException {
        logger.debug("Retrieving {}", profile.getType());

        final ProfilePersistenceHandler<T> profilePersistenceHandler = (ProfilePersistenceHandler<T>) getProfilePersistenceHandler(profile.getType());
        profile = profilePersistenceHandler.getProfile(profile);

        logger.debug("{} Retrieved With ID: {}", profile.getType(), profile.getId());
        return profile;
    }

    /**
     * API for updating {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile}
     * 
     * @param profile
     *            {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} instance that is to be updated.
     * @return generic profile object which can be of type {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile}
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T extends AbstractProfile> T updateProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        logger.debug("updating {} with ID: {}", profile.getType(), profile.getId());

        final ProfilePersistenceHandler<T> profilePersistenceHandler = (ProfilePersistenceHandler<T>) getProfilePersistenceHandler(profile.getType());
        profile = profilePersistenceHandler.updateProfile(profile);

        logger.debug("{} with ID {}, Updated ", profile.getType(), profile.getId());

        return profile;
    }

    /**
     * API for updating {@link Profiles}
     * 
     * @param profiles
     *            {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} instance that is to be updated.
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public void updateProfiles(final Profiles profiles) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        logger.debug("Updating Profiles in bulk");

        if (profiles.getTrustProfiles() != null) {
            for (final TrustProfile trustProfile : profiles.getTrustProfiles()) {
                updateProfile(trustProfile);
            }
        }

        if (profiles.getEntityProfiles() != null) {
            for (final EntityProfile entityProfile : profiles.getEntityProfiles()) {
                updateProfile(entityProfile);
            }
        }

        if (profiles.getCertificateProfiles() != null) {
            for (final CertificateProfile certificateProfile : profiles.getCertificateProfiles()) {
                updateProfile(certificateProfile);
            }
        }

        logger.debug("Profiles updated in bulk");
    }

    /**
     * API for deleting a profile based on Id/Name.
     * 
     * @param profile
     *            instance {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} with Id/name set.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileInUseException
     *             thrown when Profile is being used by other entities or profiles.
     * @throws ProfileNotFoundException
     *             thrown when profile do not exists in DB.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T extends AbstractProfile> void deleteProfile(final T profile) throws InvalidProfileException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {
        logger.debug("Deleting {}", profile.getType());

        final ProfilePersistenceHandler<T> profilePersistenceHandler = (ProfilePersistenceHandler<T>) getProfilePersistenceHandler(profile.getType());
        profilePersistenceHandler.deleteProfile(profile);

        logger.debug("{} Deleted", profile.getType());
    }

    /**
     * API for deleting a profiles based on Id/Name.
     * 
     * @param profiles
     *            instance {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} with Id/name set.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when profile do not exists in DB.
     * @throws ProfileInUseException
     *             thrown when Profile is being used by other entities or profiles.
     */
    public void deleteProfiles(final Profiles profiles) throws InvalidProfileException, ProfileServiceException, ProfileNotFoundException, ProfileInUseException {
        logger.debug("Deleting Profiles in bulk");

        if (profiles.getTrustProfiles() != null) {
            for (final TrustProfile trustProfile : profiles.getTrustProfiles()) {
                deleteProfile(trustProfile);
            }
        }

        if (profiles.getEntityProfiles() != null) {
            for (final EntityProfile entityProfile : profiles.getEntityProfiles()) {
                deleteProfile(entityProfile);
            }
        }

        if (profiles.getCertificateProfiles() != null) {
            for (final CertificateProfile certificateProfile : profiles.getCertificateProfiles()) {
                deleteProfile(certificateProfile);
            }
        }

        logger.debug("Profiles deleted in bulk");
    }

    /**
     * API for checking the profile name availability
     * 
     * @param name
     *            Name to be checked for availability.
     * @param profileType
     *            {@link ProfileType} in which name to be checked.
     * @return boolean value true or false
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public boolean isNameAvailable(final String name, final ProfileType profileType) throws InvalidProfileException, ProfileServiceException {
        logger.debug("availability of name in trust profiles {}", name);
        return getProfilePersistenceHandler(profileType).isNameAvailable(name);
    }

    private ProfilePersistenceHandler<? extends AbstractProfile> getProfilePersistenceHandler(final ProfileType profileType) throws InvalidProfileException {
        final ProfilePersistenceHandler<? extends AbstractProfile> profilePersistencehandler = profilePersistenceHandlerFactory.getProfilePersistenceHandler(profileType);
        return profilePersistencehandler;
    }

    private Profiles getProfilesByType(final List<ProfileType> profileTypes) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final Profiles pkiProfiles = new Profiles();

        for (final ProfileType profileType : profileTypes) {
            switch (profileType) {
            case TRUST_PROFILE:
                pkiProfiles.setTrustProfiles(getProfilePersistenceHandler(profileType).getProfiles(profileType).getTrustProfiles());
                break;

            case CERTIFICATE_PROFILE:
                pkiProfiles.setCertificateProfiles(getProfilePersistenceHandler(profileType).getProfiles(profileType).getCertificateProfiles());
                break;

            case ENTITY_PROFILE:
                pkiProfiles.setEntityProfiles(getProfilePersistenceHandler(profileType).getProfiles(profileType).getEntityProfiles());
                break;

            default:
                throw new InvalidProfileException(ProfileServiceErrorCodes.UNKNOWN_PROFILETYPE);
            }
        }

        return pkiProfiles;
    }

    /**
     * This method retrives the Entity Profiles based on Category
     * 
     * @param entityCategory
     * @return List of entityProfiles based on entity category
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when the Entity Profile is not found with the specified category.
     * @throws EntityCategoryNotFoundException
     *             thrown when the given category is not found in db.
     * @throws InvalidEntityCategoryException
     *             thrown when Invalid Category is provided.
     */
    public List<EntityProfile> getEntityProfilesByCategory(final EntityCategory entityCategory) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException,
            ProfileNotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException {

        final ProfilePersistenceHandler<EntityProfile> profilesPersistenceHandler = (ProfilePersistenceHandler<EntityProfile>) getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE);
        return profilesPersistenceHandler.getEntityProfilesByCategory(entityCategory);
    }

    /**
     * Returns active profiles of profileType
     * 
     * @param profileTypes
     *            list of {@link ProfileType}
     * @return List of activeProfiles based on given list of profile types
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public Profiles getActiveProfiles(final ProfileType[] profileTypes, final boolean isCompleteProfileRequired) throws InvalidProfileException, InvalidProfileAttributeException,
            ProfileServiceException {
        logger.debug("Retrieving all profiles of Type: {}", new Object[] { profileTypes });

        final List<ProfileType> profileTypeList = Arrays.asList(profileTypes);
        final Profiles activeProfiles = getActiveProfilesList(profileTypeList, isCompleteProfileRequired);

        logger.debug("{}s Retrieved", activeProfiles);

        return activeProfiles;
    }

    private Profiles getActiveProfilesList(final List<ProfileType> profileTypes, final boolean isCompleteProfileRequired) throws InvalidProfileException, InvalidProfileAttributeException,
            ProfileServiceException {
        final Profiles profiles = new Profiles();

        for (final ProfileType profileType : profileTypes) {

            switch (profileType) {

            case TRUST_PROFILE:
                final List<TrustProfile> activeTrustProfiles = getProfilePersistenceHandler(ProfileType.TRUST_PROFILE).getActiveProfiles(profileType, isCompleteProfileRequired).getTrustProfiles();
                profiles.setTrustProfiles(activeTrustProfiles);
                break;
            case CERTIFICATE_PROFILE:
                final List<CertificateProfile> activeCertificateProfiles = getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE).getActiveProfiles(profileType, isCompleteProfileRequired)
                        .getCertificateProfiles();
                profiles.setCertificateProfiles(activeCertificateProfiles);
                break;
            case ENTITY_PROFILE:
                final List<EntityProfile> activeEntityProfiles = getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE).getActiveProfiles(profileType, isCompleteProfileRequired).getEntityProfiles();
                profiles.setEntityProfiles(activeEntityProfiles);
                break;

            default:
                throw new IllegalArgumentException(ProfileServiceErrorCodes.UNKNOWN_PROFILETYPE);

            }
        }

        return profiles;
    }

    /**
     * This method returns count of {@link CertificateProfile}/{@link EntityProfile}/{@link TrustProfile} that match with the given filter criteria
     * 
     * @param profilesFilter
     *            ProfilesFilter object specifying criteria based on which entities have to be filtered
     * @return integer count of entities matching given criteria
     * 
     */

    public int getProfilesCountByFilter(final ProfilesFilter profilesFilter) {

        int count = 0;

        if (ValidationUtils.isNullOrEmpty(profilesFilter.getType())) {

            count += getProfilePersistenceHandler(ProfileType.CERTIFICATE_PROFILE).getProfilesCountByFilter(profilesFilter);
            count += getProfilePersistenceHandler(ProfileType.ENTITY_PROFILE).getProfilesCountByFilter(profilesFilter);
            count += getProfilePersistenceHandler(ProfileType.TRUST_PROFILE).getProfilesCountByFilter(profilesFilter);
            return count;
        }

        if (profilesFilter.getName() == "") {
            profilesFilter.setName("%");
        }

        for (final ProfileType profileType : profilesFilter.getType()) {
            count += getProfilePersistenceHandler(profileType).getProfilesCountByFilter(profilesFilter);
        }

        return count;

    }

    /**
     * This method returns list of combinations of {@link CertificateProfile}/{@link EntityProfile}/{@link TrustProfile} that match with the given filter criteria and that lie between given offset,
     * limit values.
     * 
     * @param profilesFilter
     *            ProfilesFilter object specifying criteria, offset, limit values based on which entities have to be filtered
     * @return list of profiles between given offset, limit values matching given criteria
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public List<AbstractProfile> getProfileDetails(final ProfilesFilter profilesFilter) throws ProfileServiceException {

        return filteredProfilesFetchHandler.getProfileDetails(profilesFilter);

    }

    /**
     * Method used to get the modifiable status of {@link CertificateProfile} and {@link EntityProfile}
     * 
     * @param profile
     * @return boolean
     * @throws InvalidProfileException
     *             thrown when the given profile is invalid.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID.
     */
    public <T extends AbstractProfile> boolean getModifiableStatus(final T profile) throws InvalidProfileException, ProfileServiceException {

        final ProfilePersistenceHandler<T> profilePersistenceHandler = (ProfilePersistenceHandler<T>) getProfilePersistenceHandler(profile.getType());
        return profilePersistenceHandler.getProfileModifiableStatus(profile);
    }

    /**
     * API for retrieving {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile}
     *
     * @param profileTypes
     *            ProfileType specifies the type of profiles to be exported.It accepts Variable argument values namely CertificateProfile,
     *            TrustProfile, EntityProfile.
     * @return Instance of {@link Profiles} containing list of {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} instances
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public Profiles getProfilesForImport(final ProfileType... profileTypes)
            throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {

        logger.debug("Retrieving all profiles of Type: {}", new Object[] { profileTypes });

        final List<ProfileType> profileTypeList = Arrays.asList(profileTypes);
        final Profiles pkiProfiles = getProfilesByTypeForImport(profileTypeList);

        logger.debug("{}s Retrieved", pkiProfiles);

        return pkiProfiles;
    }

    /**
     * API for retrieving the Profile used for Import profiles operation based on Id/Name.
     *
     * @param profile
     *            instance {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} with Id/name set.
     * @return instance of {@link TrustProfile} / {@link EntityProfile} / {@link CertificateProfile} found in DB.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileNotFoundException
     *             thrown when profile do not exists in DB.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws MissingMandatoryFieldException
     *             thrown when the provided input is invalid.
     */
    public <T extends AbstractProfile> T getProfileForImport(T profile) throws InvalidProfileException, InvalidProfileAttributeException,
            ProfileNotFoundException, ProfileServiceException, MissingMandatoryFieldException {
        logger.debug("Retrieving {}", profile.getType());

        final ProfilePersistenceHandler<T> profilePersistenceHandler = (ProfilePersistenceHandler<T>) getProfilePersistenceHandler(profile.getType());
        profile = profilePersistenceHandler.getProfileForImport(profile);

        logger.debug("{} Retrieved With ID: {}", profile.getType(), profile.getId());
        return profile;
    }

    private Profiles getProfilesByTypeForImport(final List<ProfileType> profileTypes) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final Profiles pkiProfiles = new Profiles();

        for (final ProfileType profileType : profileTypes) {
            switch (profileType) {
            case TRUST_PROFILE:
                pkiProfiles.setTrustProfiles(getProfilePersistenceHandler(profileType).getProfilesForImport(profileType).getTrustProfiles());
                break;

            case CERTIFICATE_PROFILE:
                pkiProfiles.setCertificateProfiles(getProfilePersistenceHandler(profileType).getProfilesForImport(profileType).getCertificateProfiles());
                break;

            case ENTITY_PROFILE:
                pkiProfiles.setEntityProfiles(getProfilePersistenceHandler(profileType).getProfilesForImport(profileType).getEntityProfiles());
                break;

            default:
                throw new InvalidProfileException(ProfileServiceErrorCodes.UNKNOWN_PROFILETYPE);
            }
        }

        return pkiProfiles;
    }

}
