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
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.persistence.PersistenceException;
import javax.persistence.TransactionRequiredException;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.ProfileQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;
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
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

/**
 * This class is responsible for {@link CertificateProfile} DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model {@link CertificateProfile} to JPA Entity {@link CertificateProfileData}</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model {@link CertificateProfile} if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractProfile} i.e., {@link TrustProfile} /{@link EntityProfile}/{@link CertificateProfile}.
 */
@ProfileQualifier(ProfileType.CERTIFICATE_PROFILE)
public class CertificateProfilePersistenceHandler<T extends AbstractProfile> extends AbstractProfilePersistenceHandler<T> {

    private static final String CERTIFICATE_PROFILE_ID = "certificateProfileData";
    private static final String IS_ENTITY_PROFILE_ACTIVE = "active";

    private static final String FILTER_QUERY_FOR_COUNT = "select count(*) from CertificateProfileData e where e.name like :certificateProfileName and (e.active = :status_active or e.active != :status_inactive) ";
    private static final String queryForFetchActiveCertProfiles = "select id,name from certificateprofile where is_active=true";

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
        profiles.setCertificateProfiles((List<CertificateProfile>) getProfiles(CertificateProfileData.class, profileType));
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
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileException
     *             Thrown when the given profile is invalid
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile has invalid attribute
     * @throws MissingMandatoryFieldException
     *             Thrown when the input arguments are invalid.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T getProfile(final T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException {
        final CertificateProfileData certificateProfileData = getProfileData(profile, CertificateProfileData.class);
        return (T) getProfileMapper(profile.getType()).toAPIFromModel(certificateProfileData);
    }

    /**
     * This method is used for delete operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>Delete from DB if not being used any other JPA Entities.</li>
     * <li>Form the Response Object and return.</li>
     * </ul>
     *
     * @param profile
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that is to be deleted.
     * @return {@link ProfileManagerResponse} with status messages set.
     *
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile has invalid attribute
     * @throws MissingMandatoryFieldException
     *             Thrown when the input arguments are invalid.
     * @throws ProfileInUseException
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public void deleteProfile(final T profile) throws InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {

        final CertificateProfileData certificateProfileData = getProfileData(profile, CertificateProfileData.class);

        try {
            checkCertificateProfileMapped(certificateProfileData);
            persistenceManager.deleteEntity(certificateProfileData);
        } catch (final TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction error occurred while deleting Certificate Profile. {}", transactionRequiredException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
    }

    /**
     * get the {@link EntityProfileData} profile based on {@link CertificateProfileData}.
     *
     * @param profile
     *            instance of {@link CertificateProfile} with Id set.
     * @return Instance of ({@link EntityProfileData}) retrieved.
     * @throws ProfileInUseException
     *             Thrown in case of validating the Certificate Profile
     * @throws ProfileServiceException
     *             Thrown in case of internal db error occurs
     */
    private void checkCertificateProfileMapped(final CertificateProfileData profileData) throws ProfileInUseException, ProfileServiceException {

        List<EntityProfileData> entityProfileDatas;
        final HashMap<String, Object> attributes = new HashMap<String, Object>();

        attributes.put(CERTIFICATE_PROFILE_ID, profileData.getId());
        attributes.put(IS_ENTITY_PROFILE_ACTIVE, true);

        try {
            entityProfileDatas = persistenceManager.findEntitiesWhere(EntityProfileData.class, attributes);

            if (entityProfileDatas.size() > 0) {

                final Iterator<EntityProfileData> iterator = entityProfileDatas.iterator();
                final List<String> entityProfileNames = new ArrayList<String>();

                while (iterator.hasNext()) {
                    final EntityProfileData entityProfileData = iterator.next();
                    entityProfileNames.add(entityProfileData.getName());
                }

                throw new ProfileInUseException(ProfileServiceErrorCodes.CERTIFICATEPROFILE_IN_USE + entityProfileNames);
            }

        } catch (final PersistenceException persistenceException) {
            logger.error("SQL Exception occurred while getting linked entity Profiles. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING_PROFILE, persistenceException);
        }
    }

    /**
     * This method is used to check the availability of Name used for {@link CertificateProfile}
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
            getProfileByName(name, CertificateProfileData.class);
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
    public List<T> getEntityProfilesByCategory(final EntityCategory entityCategory) throws EntityCategoryException, EntityCategoryNotFoundException, InvalidEntityCategoryException,
            ProfileNotFoundException {
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
     * @return count of {@link CertificateProfile} that are retrieved from DB.
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

        attributes.put("certificateProfileName", profilesFilter.getName());
        attributes.put("status_active", profilesFilter.getStatus().isActive());
        attributes.put("status_inactive", profilesFilter.getStatus().isInactive());

        try {

            logger.debug("Query in getEntitiesCountWithFilter: " + FILTER_QUERY_FOR_COUNT);
            count = (int) persistenceManager.findEntitiesCountByAttributes(FILTER_QUERY_FOR_COUNT, attributes);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of CertificateProfiles that match with given filter criteria. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "Certificate Profile.", persistenceException);
        }

        return count;
    }

    private int getProfilesCountWithoutFilter() throws ProfileServiceException {
        int count = 0;

        try {
            count = (int) persistenceManager.getEntitiesCount(CertificateProfileData.class);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error in retrieving count of CertificateProfiles that match with given filter criteria. {}", persistenceException.getMessage());
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_RETRIEVING + "CertificateProfile.", persistenceException);
        }

        return count;
    }

    /**
     * This method is used for getting all active certificate profiles. It Does the following operation:
     *
     * Retrieve complete JPA Entity instances of certificate profiles if boolean flag set to true.Else just return id and names of all certificate profiles.
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
            profiles.setCertificateProfiles((List<CertificateProfile>) getActiveProfiles(CertificateProfileData.class, profileType));
        } else {
            profiles.setCertificateProfiles(getActiveProfilesIdAndName());
        }

        return profiles;
    }

    private List<CertificateProfile> getActiveProfilesIdAndName() throws ProfileServiceException {
        final List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();

        // To-Do    : native query has to be migrated to JPQL - http://jira-nam.lmera.ericsson.se/browse/TORF-114083
        final List<Object[]> entities = fetchActiveProfilesIdAndName(queryForFetchActiveCertProfiles);

        for (final Object[] entity : entities) {
            final CertificateProfile certificateProfile = new CertificateProfile();

            certificateProfile.setId(((BigInteger) entity[0]).longValue());
            certificateProfile.setName((String) entity[1]);

            certificateProfiles.add(certificateProfile);
        }

        return certificateProfiles;
    }

    /**
     * This method is used for retrieving profiles in bulk which are update for import profiles operation. It Does the following operation:
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
    public Profiles getProfilesForImport(final ProfileType profileType)
            throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        final Profiles profiles = new Profiles();
        profiles.setCertificateProfiles((List<CertificateProfile>) getProfilesForImport(CertificateProfileData.class, profileType));
        return profiles;
    }

    /**
     * This method is used for retrieving profile which is used for Profile Import/update operation. It Does the following operation:
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
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileException
     *             Thrown when the given profile is invalid
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile has invalid attribute
     * @throws MissingMandatoryFieldException
     *             Thrown when the input arguments are invalid.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    @Override
    public T getProfileForImport(final T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException {
        final CertificateProfileData certificateProfileData = getProfileData(profile, CertificateProfileData.class);
        return profileModelMapperFactory.getProfileExportModelMapper(profile.getType()).toAPIFromModel(certificateProfileData);
    }

}
