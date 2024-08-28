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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * This class is responsible for {@link EntityProfile} DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model {@link EntityProfile} to JPA Entity {@link EntityProfileData}</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model {@link EntityProfile} if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractProfile} i.e., {@link TrustProfile} /{@link EntityProfile}/{@link CertificateProfile}.
 */
@ProfileQualifier(ProfileType.ENTITY_PROFILE)
public class EntityProfilePersistenceHandler<T extends AbstractProfile> extends AbstractProfilePersistenceHandler<T> {

    private static final String entityQuery = "select e from EntityData e join e.entityProfileData ep where ep.id=:entity_profile_id";

    private static final String caEntityQuery = "select e from CAEntityData e join e.entityProfileData ep where ep.id=:entity_profile_id";

    private static final String ENTITY_CATEGORY_ID = "entityCategoryData";

    private static final String NAME = "name";

    private static final String FILTER_QUERY_FOR_COUNT = "select count(*) from EntityProfileData e where e.name like :entityProfileName and (e.active = :status_active or e.active != :status_inactive)";

    private static final String queryForFetchActiveEntityProfiles = "select id,name from entityprofile where is_active=true";

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param profile
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} with Id/name Set.
     * @return {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is retrieved successfully.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public Profiles getProfiles(final ProfileType profileType) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final Profiles profiles = new Profiles();
        profiles.setEntityProfiles((List<EntityProfile>) getProfiles(EntityProfileData.class, profileType));
        return profiles;
    }

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return {@link java.util.List} of {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that are retrieved from DB.
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileNotFoundException
     *             thrown when the profile is not found in system.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T getProfile(final T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileNotFoundException,
            ProfileServiceException {
        final EntityProfileData entityProfileData = getProfileData(profile, EntityProfileData.class);
        return (T) getProfileMapper(profile.getType()).toAPIFromModel(entityProfileData);
    }

    private boolean isEntityProfileMapped(final EntityProfileData entityProfileData) throws ProfileServiceException{
        final Map<String, Object> hmAttributes = new HashMap<String, Object>();
        hmAttributes.put("entity_profile_id", entityProfileData.getId());
        List<EntityData> endEntityList = null;
        List<CAEntityData> caEntityList = null;
        try {
            endEntityList = persistenceManager.findEntitiesByAttributes(EntityData.class, entityQuery, hmAttributes);
            caEntityList = persistenceManager.findEntitiesByAttributes(CAEntityData.class, caEntityQuery, hmAttributes);
        } catch (final PersistenceException e) {
            logger.error("SQL Exception occurred while retrieving Entity Profile. {}", e.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, e);
        }
        return (endEntityList.isEmpty() && caEntityList.isEmpty());
    }

    /**
     * This method is used for delete operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>Delete from DB if is not being used any other JPA Entities.</li>
     * <li>Form the Response Object and return.</li>
     * </ul>
     *
     * @param profile
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is to be deleted.
     * @return {@link ProfileManagerResponse} with status messages set.
     *
     * @throws InvalidProfileAttributeException
     *             Thrown when the profile has invalid attribute.
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileInUseException
     *             Thrown when the Profile is mapped to any entities.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public void deleteProfile(final T profile) throws InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {
        final EntityProfileData entityProfileData = getProfileData(profile, EntityProfileData.class);

        if (isEntityProfileMapped(entityProfileData)) {
            try {
                persistenceManager.deleteEntity(entityProfileData);
            } catch (final PersistenceException e) {
                logger.error("SQL Exception occurred while deleting Entity Profile. {}", e.getMessage());
                throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_DELETING_PROFILE, e);
            }
        } else {
            throw new ProfileInUseException(ProfileServiceErrorCodes.ENTITYPROFILE_IN_USE);
        }
    }

    /**
     * This method is used to check the availability of Name used for {@link EntityProfile}
     *
     * @param name
     *            name of profile to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     *
     */
    @Override
    public boolean isNameAvailable(final String name) throws ProfileServiceException {
        try {
            getProfileByName(name, EntityProfileData.class);
        } catch (final ProfileNotFoundException e) {
            logger.debug(ProfileServiceErrorCodes.NO_PROFILE_FOUND_WITH_NAME + name, e);
            return true;
        }
        return false;
    }

    /**
     * This method is used to check the availability of Name used for {@link EntityProfile}
     *
     * @param name
     *            name of profile to be checked
     * @return <code>true</code> or <code>false</code>
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws EntityCategoryNotFoundException
     *             Thrown when the given entity category is not found in the system.
     * @throws InvalidEntityCategoryException
     *             Thrown when the given entity category is invalid.
     * @throws InvalidProfieException
     *             Thrown when the given profile is invalid.
     * @throws InvalidProfileAttributeException
     *             Thrown when the profile has invalid attribute.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public List<T> getEntityProfilesByCategory(final EntityCategory entityCategory) throws  CANotFoundException, EntityCategoryNotFoundException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException {
        ModelMapper modelMapper;
        List<EntityProfileData> entityProfileDatas;
        try {
            final EntityCategoryData entityCategoryData = persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME);
            final Map<String, Object> input = new HashMap<String, Object>();
            input.put(ENTITY_CATEGORY_ID, entityCategoryData);

            logger.debug("Fetching entity profiles by category from the database");
            entityProfileDatas = persistenceManager.findEntitiesWhere(EntityProfileData.class, input);
            modelMapper = getProfileMapper(ProfileType.ENTITY_PROFILE);
        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while getting linked entities. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILES, persistenceException);
        }
        logger.info("Mapping model to the api");
        final List<EntityProfile> entitiesList = modelMapper.toAPIModelList(entityProfileDatas);
        return (List<T>) entitiesList;
    }

    /**
     * This method is used for getting count of profiles applying filter criteria, if any specified. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances or JPA Entity instances based on filter if specified, .</li>
     * <li>Return the count of such instances.</li>
     * </ul>
     *
     * @param profilesFilter
     *            specifies criteria based on which profiles have to be filtered
     *
     * @return count of {@link EntityProfile} that are retrieved from DB.
     *
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    public int getProfilesCountByFilter(final ProfilesFilter profilesFilter) throws ProfileServiceException {
        int count = 0;

        if (!ValidationUtils.isNullOrEmpty(profilesFilter.getType())) {
            count = getProfilesCountWithFilter(profilesFilter);
        } else {
            count = getProfilesCountWithoutFilter();
        }

        return count;
    }

    private int getProfilesCountWithFilter(final ProfilesFilter profilesFilter) throws ProfileServiceException {
        int count = 0;
        final Map<String, Object> attributes = new HashMap<String, Object>();

        attributes.put("entityProfileName", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());
        try {

            logger.debug("Query in getProfilesCountWithFilter: " + FILTER_QUERY_FOR_COUNT);
            count = (int) persistenceManager.findEntitiesCountByAttributes(FILTER_QUERY_FOR_COUNT, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of EntityProfiles that match with given filter criteria. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "Entity Profile.", persistenceException);
        }

        return count;
    }

    private int getProfilesCountWithoutFilter() throws ProfileServiceException {
        int count = 0;

        try {
            count = (int) persistenceManager.getEntitiesCount(EntityProfileData.class);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of EntityProfiles that match with given filter criteria. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "EntityProfile.", persistenceException);
        }

        return count;
    }

    /**
     * This method is used for getting all active entity profiles. It Does the following operation:
     *
     * Retrieve complete JPA Entity instances of all {@link EntityProfile} if boolean flag set to true. Else just return id and names of all {@link EntityProfile}.
     *
     * @param profileType
     *            type of profiles to be fetched
     *
     * @return {@link Profiles} that are retrieved from DB.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public Profiles getActiveProfiles(final ProfileType profileType, final boolean isCompleteProfileRequired) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final Profiles profiles = new Profiles();

        if (isCompleteProfileRequired) {
            profiles.setEntityProfiles((List<EntityProfile>) getActiveProfiles(EntityProfileData.class, profileType));
        } else {
            profiles.setEntityProfiles(getActiveProfilesIdAndName());
        }

        return profiles;
    }

    private List<EntityProfile> getActiveProfilesIdAndName() throws ProfileServiceException {
        final List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();

        // To-Do    : native query has to be migrated to JPQL - http://jira-nam.lmera.ericsson.se/browse/TORF-114083
        final List<Object[]> entities = fetchActiveProfilesIdAndName(queryForFetchActiveEntityProfiles);

        for (final Object[] entity : entities) {
            final EntityProfile entityProfile = new EntityProfile();

            entityProfile.setId(((BigInteger) entity[0]).longValue());
            entityProfile.setName((String) entity[1]);

            entityProfiles.add(entityProfile);
        }

        return entityProfiles;
    }

    /**
     * This method is used for retrieving EntityProfiles in bulk which are used for import profiles operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param profile
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} with Id/name Set.
     * @return {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is retrieved successfully.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public Profiles getProfilesForImport(final ProfileType profileType)
            throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final Profiles profiles = new Profiles();
        profiles.setEntityProfiles((List<EntityProfile>) getProfilesForImport(EntityProfileData.class, profileType));
        return profiles;
    }

    /**
     * This method is used for retrieving profile in bulk which is used for import/update profile operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return {@link java.util.List} of {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that are retrieved from DB.
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileNotFoundException
     *             thrown when the profile is not found in system.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T getProfileForImport(final T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException,
            MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException {
        final EntityProfileData entityProfileData = getProfileData(profile, EntityProfileData.class);
        return profileModelMapperFactory.getProfileExportModelMapper(profile.getType()).toAPIFromModel(entityProfileData);
    }

}
