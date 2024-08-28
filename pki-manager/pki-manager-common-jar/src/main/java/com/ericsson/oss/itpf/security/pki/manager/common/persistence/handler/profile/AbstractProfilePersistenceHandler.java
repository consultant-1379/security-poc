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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.SearchType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.profile.ProfileModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * This class implements some of the methods in {@link ProfilePersistenceHandler} And this class holds common methods for DB CRUD Operation.
 *
 * @param <T>
 *            Class extending {@link AbstractProfile} i.e., {@link TrustProfile} /{@link EntityProfile}/{@link CertificateProfile}.
 */
public abstract class AbstractProfilePersistenceHandler<T extends AbstractProfile> implements ProfilePersistenceHandler<T> {

    @Inject
    Logger logger;

    @Inject
    ProfileModelMapperFactory profileModelMapperFactory;

    @Inject
    PersistenceManager persistenceManager;

    private final static String NAME_PATH = "name";

    /**
     * This method calls the {@link ProfileModelMapperFactory} and get the appropriate instance of {@link ModelMapper}
     *
     * @return Instance of {@link ModelMapper}
     */
    protected ModelMapper getProfileMapper(final ProfileType profileType) throws InvalidProfileException {
        final ModelMapper profileMapper = profileModelMapperFactory.getProfileModelMapper(profileType);
        return profileMapper;
    }

    /**
     * This method is used for create operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Persist into DB.</li>
     * <li>Retrieve created Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param profile
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is to be persisted.
     * @return {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is persisted successfully.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     * @throws ProfileAlreadyExistsException
     *             Thrown when the Profile already exists in system.
     */
    @Override
    public T createProfile(T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException, ProfileAlreadyExistsException {
        try {
            final AbstractProfileData profileData = getProfileMapper(profile.getType()).fromAPIToModel(profile);
            persistenceManager.createEntity(profileData);

            final AbstractProfileData profileDataCreated = persistenceManager.findEntityByName(profileData.getClass(), profile.getName(), NAME_PATH);

            profile = getProfileMapper(profile.getType()).toAPIFromModel(profileDataCreated);
        } catch (final EntityExistsException entityExistsException) {
            logger.error("Profile Already Exists {}", entityExistsException.getMessage());
            throw new ProfileAlreadyExistsException(ProfileServiceErrorCodes.PROFILE_EXISTS_ALREADY, entityExistsException);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating Profile {}", transactionRequiredException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final CANotFoundException invalidCAException) {
            logger.error("CANotFoundException Error in creating Profile {}", invalidCAException.getMessage());
            throw new CANotFoundException(invalidCAException.getMessage(), invalidCAException);
        } catch (final PersistenceException exception) {
            logger.error("Error in creating Profiles. {}", exception.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_CREATING_PROFILE, exception);
        }
        return profile;
    }

    /**
     * This method is used for update operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Update in DB.</li>
     * <li>Retrieve updated Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param profile
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is to be updated.
     * @return {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is updated successfully.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T updateProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {

        try {
            final AbstractProfileData profileData = getProfileMapper(profile.getType()).fromAPIToModel(profile);
            persistenceManager.updateEntity(profileData);

            final AbstractProfileData profileDataUpdated = persistenceManager.findEntityByName(profileData.getClass(), profile.getName(), NAME_PATH);
            profile = getProfileMapper(profile.getType()).toAPIFromModel(profileDataUpdated);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating Profile {}", transactionRequiredException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (final PersistenceException exception) {
            logger.error("Error in updating Profiles. {}", exception.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_UPDATING_PROFILE, exception);
        }
        return profile;
    }

    /**
     * This method retrieves all the JPA Entities based on Class Type Specified.
     *
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @param profileType
     * @return {@link java.util.List} of instances of ( {@link EntityProfileData}/{@link TrustProfileData}/ CertifiacteProfileData )
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    public <E extends AbstractProfileData> List<T> getProfiles(final Class<E> profileDataType, final ProfileType profileType) throws InvalidProfileException, InvalidProfileAttributeException,
            ProfileServiceException {
        final List<T> profiles = new ArrayList<T>();
        try {
            final List<E> profileDataList = persistenceManager.getAllEntityItems(profileDataType);

            for (final E profileData : profileDataList) {
                final T profile = getProfileMapper(profileType).toAPIFromModel(profileData);
                profiles.add(profile);
            }
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profiles. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILES, persistenceException);
        }
        return profiles;
    }

    /**
     * This method is used for retrieve operation based on id. It Does the following operation:
     * <ul>
     * <li>Get the Id.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param id
     *            id, using which JPA Entity to be retrieved
     *
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @return {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData that is retrieved successfully.
     *
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    protected <E extends AbstractProfileData> E getProfileById(final long id, final Class<E> profileDataType) throws ProfileNotFoundException, ProfileServiceException {
        E profileData = null;

        try {
            profileData = persistenceManager.findEntity(profileDataType, id);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profile. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, persistenceException);
        }

        if (profileData == null) {
            throw new ProfileNotFoundException(ProfileServiceErrorCodes.NO_PROFILE_FOUND_WITH_ID + id);
        }
        return profileData;
    }

    /**
     * This method is used for retrieve operation based on name. It Does the following operation:
     * <ul>
     * <li>Get the Name.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param name
     *            name, using which JPA Entity to be retrieved
     *
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @return {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData that is retrieved successfully.
     *
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    protected <E extends AbstractProfileData> E getProfileByName(final String name, final Class<E> profileDataType) throws ProfileNotFoundException, ProfileServiceException {
        E profileData = null;

        try {
            profileData = persistenceManager.findEntityByName(profileDataType, name, NAME_PATH);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profile. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, persistenceException);
        }
        if (profileData == null) {
            throw new ProfileNotFoundException(ProfileServiceErrorCodes.NO_PROFILE_FOUND_WITH_NAME + name);
        }
        return profileData;
    }

    /**
     * This method is used for retrieve operation based on id and Name. It Does the following operation:
     * <ul>
     * <li>Get the Id and Name.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param id
     *            id, using which JPA Entity to be retrieved
     * @param name
     *            name, using which JPA Entity to be retrieved
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @return {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData that is retrieved successfully.
     *
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    protected <E extends AbstractProfileData> E getProfileByNameAndId(final long id, final String name, final Class<E> profileDataType) throws ProfileNotFoundException, ProfileServiceException {
        E profileData = null;

        try {
            profileData = persistenceManager.findEntityByIdAndName(profileDataType, id, name, NAME_PATH);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profile. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, persistenceException);
        }
        if (profileData == null) {
            throw new ProfileNotFoundException(ProfileServiceErrorCodes.NO_PROFILE_FOUND_WITH_ID_AND_NAME + id + " " + name);
        }
        return profileData;
    }

    /**
     * get the {@link SearchType} whether the profile needs to be retrieved based on id or name.
     *
     * @param id
     *            id, using which JPA Entity to be retrieved
     * @param name
     *            name, using which JPA Entity to be retrieved
     * @return {@link SearchType}
     */
    protected SearchType getProfileSearchType(final long id, final String name) throws MissingMandatoryFieldException {
        if (id == 0 && name == null) {
            logger.error("Invalid Arguments: Atleast id or name should be specified.");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ID_OR_NAME_SHOULD_PRESENT);
        }

        if (id != 0 && name != null) {
            return SearchType.BOTH;
        } else {
            if (id != 0) {
                return SearchType.ID;
            } else {
                return SearchType.NAME;
            }
        }
    }

    /**
     * Retrieve the Profile based on {@link SearchType}. This method categorize the {@link SearchType} and call the respective method to retrieve a profile.
     *
     * @param profile
     *            instance of {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} with Id/Name set.
     * @param profileDataType
     *            JPA Entity Class ( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @return Instance of ( {@link EntityProfileData}/ {@link TrustProfileData} / CertifiacteProfileData ) retrieved.
     */
    protected <E extends AbstractProfileData> E getProfileData(final T profile, final Class<E> profileDataType) throws InvalidProfileAttributeException, MissingMandatoryFieldException,
            ProfileNotFoundException, ProfileServiceException {
        E profileData;

        final SearchType searchType = getProfileSearchType(profile.getId(), profile.getName());

        switch (searchType) {
        case ID:
            profileData = getProfileById(profile.getId(), profileDataType);
            break;
        case NAME:
            profileData = getProfileByName(profile.getName(), profileDataType);
            break;
        case BOTH:
            profileData = getProfileByNameAndId(profile.getId(), profile.getName(), profileDataType);
            break;
        default:
            throw new InvalidProfileAttributeException("Invalid Id or Name : " + searchType);
        }

        return profileData;
    }

    /**
     * Method used to fetch the modifiable status of {@link CertificateProfile}
     *
     * @param profile
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public boolean getProfileModifiableStatus(final T profile) throws InvalidProfileException, ProfileNotFoundException, ProfileServiceException {
        AbstractProfileData profileData;

        try {
            profileData = getProfileMapper(profile.getType()).fromAPIToModel(profile);
            final String profileDatas = profileData.toString();
            logger.debug("Profile data received : {}", profileDatas);
            profileData = persistenceManager.findEntity(profileData.getClass(), profile.getId());
            if (profileData == null) {
                logger.error("No profile found with ID: {}", profile.getId());
                throw new ProfileNotFoundException(ProfileServiceErrorCodes.NO_PROFILE_FOUND_WITH_ID + profile.getId());
            }
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profile. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, persistenceException);
        }
        return profileData.isModifiable();

    }

    /**
     * This method retrieves all active profiles based on Profile Type Specified.
     *
     *
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @return {@link java.util.List} of instances of ( {@link EntityProfileData}/{@link TrustProfileData}/ CertifiacteProfileData )
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    public <E extends AbstractProfileData> List<T> getActiveProfiles(final Class<E> profileDataType, final ProfileType profileType) throws InvalidProfileException, InvalidProfileAttributeException,
            ProfileServiceException {
        final List<T> profiles = new ArrayList<T>();

        try {
            final HashMap<String, Object> parameters = new HashMap<String, Object>();
            parameters.put("active", true);

            final List<E> profileDataList = persistenceManager.findEntitiesWhere(profileDataType, parameters);

            for (final E profileData : profileDataList) {
                final T profile = getProfileMapper(profileType).toAPIFromModel(profileData);
                profiles.add(profile);
            }

        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving active profiles. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ACTIVE_PROFILES, persistenceException);
        }

        return profiles;
    }

    /**
     * This method retrieves ids and names of all active profiles based on Profile Type Specified.
     *
     *
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @return {@link java.util.List} of instances of ( {@link EntityProfileData}/{@link TrustProfileData}/{@link CertifiacteProfileData})
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    public <E extends AbstractProfileData> List<Object[]> fetchActiveProfilesIdAndName(final String queryForFetchProfiles) throws ProfileServiceException {
        List<Object[]> entities = null;

        try {
            entities = persistenceManager.findEntitiesByNativeQuery(queryForFetchProfiles);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profiles. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_ACTIVE_PROFILES, persistenceException);
        }

        return entities;
    }

    /**
     * This method retrieves all the JPA Entities used for Import profiles operation based on the ProfileType.
     *
     * @param profileDataType
     *            Class of JPA Entity( {@link EntityProfileData}/ {@link TrustProfileData}/ CertifiacteProfileData )
     * @param profileType
     * @return {@link java.util.List} of instances of ( {@link EntityProfileData}/{@link TrustProfileData}/ CertifiacteProfileData )
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    public <E extends AbstractProfileData> List<T> getProfilesForImport(final Class<E> profileDataType, final ProfileType profileType)
            throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final List<T> profiles = new ArrayList<T>();
        try {
            final List<E> profileDataList = persistenceManager.getAllEntityItems(profileDataType);

            for (final E profileData : profileDataList) {
                final T profile = profileModelMapperFactory.getProfileExportModelMapper(profileType).toAPIFromModel(profileData);
                profiles.add(profile);
            }
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while retrieving Profiles. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILES, persistenceException);
        }
        return profiles;
    }

}
