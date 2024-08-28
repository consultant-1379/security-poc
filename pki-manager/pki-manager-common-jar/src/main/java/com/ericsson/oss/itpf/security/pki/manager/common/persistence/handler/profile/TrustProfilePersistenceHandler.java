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
import javax.persistence.TransactionRequiredException;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;
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
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;

/**
 * This class is responsible for {@link TrustProfile} DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model {@link TrustProfile} to JPA Entity {@link TrustProfileData}</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model {@link TrustProfile} if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractProfile} i.e., {@link TrustProfile} /{@link EntityProfile}/{@link CertificateProfile}.
 */
@ProfileQualifier(ProfileType.TRUST_PROFILE)
public class TrustProfilePersistenceHandler<T extends AbstractProfile> extends AbstractProfilePersistenceHandler<T> {

    private final static String entityProfileQuery = "select e from EntityProfileData e join e.trustProfileDatas t where e.active in(:is_active) and t.id=:trust_profile_id";

    private static final String FILTER_QUERY_FOR_COUNT = "select count(*) from TrustProfileData e where e.name like :trustProfileName and (e.active = :status_active or e.active != :status_inactive)";

    private static final String queryForFetchActiveTrustProfiles = "select id,name from trustprofile where is_active=true";

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return {@link java.util.List} of {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that are retrieved from DB.
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
        profiles.setTrustProfiles((List<TrustProfile>) getProfiles(TrustProfileData.class, profileType));
        return profiles;
    }

    /**
     * This method is used for retrieve operation. It Does the following operation:
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
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T getProfile(final T profile) throws InvalidProfileException, InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException {
        final TrustProfileData trustProfileData = getProfileData(profile, TrustProfileData.class);
        return getProfileMapper(profile.getType()).toAPIFromModel(trustProfileData);
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
     *
     * @throws InvalidProfileAttributeException
     *             Thrown when the profile has invalid attribute.
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileInUseException
     *             Thrown when the profile is mapped with entities.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public void deleteProfile(final T profile) throws InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {

        final TrustProfileData trustProfileData = getProfileData(profile, TrustProfileData.class);

        try {
            checkTrustProfileMapped(trustProfileData);
            persistenceManager.deleteEntity(trustProfileData);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction error occurred while deleting Trust Profile. {}", transactionRequiredException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }catch (final PersistenceException exception) {
            logger.error("Error occurred while deleting Trust Profile. {}", exception.getMessage());
            throw new ProfileServiceException("Error occurred while deleting Trust Profile", exception);
        }
    }

    private void checkTrustProfileMapped(final TrustProfileData trustProfileData) throws ProfileInUseException {

        final List<String> entityProfileNames = new ArrayList<String>();
        final Map<String, Object> hmAttributes = new HashMap<String, Object>();
        hmAttributes.put("trust_profile_id", trustProfileData.getId());
        hmAttributes.put("is_active", true);

        final List<EntityProfileData> entityProfiles = persistenceManager.findEntitiesByAttributes(EntityProfileData.class, entityProfileQuery, hmAttributes);

        if (entityProfiles.size() > 0) {
            for (int i = 0; i < entityProfiles.size(); i++) {
                entityProfileNames.add(entityProfiles.get(i).getName());
            }
            throw new ProfileInUseException(ProfileServiceErrorCodes.TRUSTPROFILE_IN_USE + entityProfileNames);
        }
    }

    /**
     * This method is sued check the availability of Name used for {@link TrustProfile}
     *
     * @param name
     *            name of profile to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws InternalServiceException
     *             Thrown when any internal error occurs in system.
     *
     */
    @Override
    public boolean isNameAvailable(final String name) throws ProfileServiceException {
        try {
            getProfileByName(name, TrustProfileData.class);
        } catch (final ProfileNotFoundException e) {
            logger.debug(ProfileServiceErrorCodes.NO_PROFILE_FOUND_WITH_NAME + name, e);
            return true;
        }
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.persistence.handler.profile.ProfilePersistenceHandler#getEntitiesByCategory(com.ericsson.oss.itpf.security.pki.common.model
     * .EntityCategory)
     */
    @Override
    public List<T> getEntityProfilesByCategory(final EntityCategory entityCategory) throws EntityCategoryException, ProfileNotFoundException, EntityCategoryNotFoundException,
            InvalidEntityCategoryException {
        // TODO Auto-generated method stub
        return null;
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
     * @return count of {@link TrustProfile} that are retrieved from DB.
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

        attributes.put("trustProfileName", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());
        try {

            logger.debug("Query in getProfilesCountWithFilter: " + FILTER_QUERY_FOR_COUNT);
            count = (int) persistenceManager.findEntitiesCountByAttributes(FILTER_QUERY_FOR_COUNT, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of TrustProfiles that match with given filter criteria. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "Trust Profile.", persistenceException);
        }

        return count;
    }

    private int getProfilesCountWithoutFilter() throws ProfileServiceException {
        int count = 0;

        try {
            count = (int) persistenceManager.getEntitiesCount(TrustProfileData.class);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of TrustProfiles that match with given filter criteria. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "TrustProfile.", persistenceException);
        }

        return count;
    }

    /**
     * This method is used for getting all active trust profiles. It Does the following operation:
     *
     * Retrieve complete JPA Entity instances of all {@link TrustProfile} if boolean flag set to true. Else just return id and names of all {@link TrustProfile}.
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
            profiles.setTrustProfiles((List<TrustProfile>) getActiveProfiles(TrustProfileData.class, profileType));
        } else {
            profiles.setTrustProfiles(getActiveProfilesIdAndName());
        }

        return profiles;
    }

    private List<TrustProfile> getActiveProfilesIdAndName() throws ProfileServiceException {
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

        // To-Do    : native query has to be migrated to JPQL - http://jira-nam.lmera.ericsson.se/browse/TORF-114083
        final List<Object[]> entities = fetchActiveProfilesIdAndName(queryForFetchActiveTrustProfiles);

        for (final Object[] entity : entities) {
            final TrustProfile trustProfile = new TrustProfile();

            trustProfile.setId(((BigInteger) entity[0]).longValue());
            trustProfile.setName((String) entity[1]);

            trustProfiles.add(trustProfile);
        }

        return trustProfiles;
    }

    /**
     * This method is used for retrieving TrustProfiles in bulk which are used for import profiles operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return {@link java.util.List} of {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that are retrieved from DB.
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
        profiles.setTrustProfiles((List<TrustProfile>) getProfilesForImport(TrustProfileData.class, profileType));
        return profiles;
    }

    /**
     * This method is used for retrieving TrustProfile which is used for import/update TrustProfile operation. It Does the following operation:
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
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T getProfileForImport(final T profile) throws InvalidProfileException, InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException {
        final TrustProfileData trustProfileData = getProfileData(profile, TrustProfileData.class);
        return profileModelMapperFactory.getProfileExportModelMapper(profile.getType()).toAPIFromModel(trustProfileData);
    }

}
