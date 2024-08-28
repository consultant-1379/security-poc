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

import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.filter.ProfilesFilter;

/**
 * This class is responsible for DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model to JPA Entity</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractProfile} i.e., {@link TrustProfile} /{@link EntityProfile}/{@link CertificateProfile}.
 */
public interface ProfilePersistenceHandler<T extends AbstractProfile> {

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
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    T createProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

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
    T updateProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

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
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileException
     *             Thrown when the given entity profile is invalid.
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile has invalid attribute
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    T getProfile(T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException, MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException;

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @param profileType
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
    Profiles getProfiles(ProfileType profileType) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

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
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    void deleteProfile(T profile) throws ProfileNotFoundException, ProfileServiceException;

    /**
     * This method is sued check the availability of Name used for {@link TrustProfile} / {@link CertificateProfile} / {@link EntityProfile}
     *
     * @param name
     *            name of profile to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    boolean isNameAvailable(String name) throws ProfileServiceException;

    /**
     * This method is used to get the list of {@link EntityProfile} based on category name.
     *
     * @param entityCategory
     * @return
     * @throws EntityCategoryException
     *             Thrown when any internal error occurs in system.
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category name is not found.
     * @throws InvalidEntityCategoryException
     *             thrown when Invalid Category is provided.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             thrown when any internal error occurs in system.
     */
    List<T> getEntityProfilesByCategory(EntityCategory entityCategory) throws EntityCategoryException, EntityCategoryNotFoundException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException;

    /**
     * This method is used for getting count of profiles applying filter criteria, if any specified. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances or JPA Entity instances based on filter if specified, .</li>
     * <li>Return the count of such instances.</li>
     * </ul>
     *
     * @param profilesFilter
     *            specifies criteria based on which entities have to be filtered
     *
     * @return count of {@link CertificateProfile}/{@link EntityProfile}/ {@link TrustProfile} that are retrieved from DB.
     *
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    int getProfilesCountByFilter(ProfilesFilter profilesFilter) throws ProfileServiceException;

    /**
     * Method used to get the modifiable status of {@link CertificateProfile} and {@link EntityProfile}
     * 
     * @param profile
     * @return
     * @throws InvalidProfileException
     *             thrown when the given profile is invalid.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID.
     */
    boolean getProfileModifiableStatus(final T profile) throws InvalidProfileException, ProfileServiceException;

    /**
     * This method is used for getting all active profiles. It Does the following operation:
     *
     * Retrieve complete JPA Entity instances of given profileType if boolean flag set to true. Else just return id and names of profiles of given profileType.
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
    Profiles getActiveProfiles(ProfileType profileType, boolean isCompleteProfileRequired) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

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
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidProfileException
     *             Thrown when the given entity profile is invalid.
     * @throws InvalidProfileAttributeException
     *             Thrown when the given profile has invalid attribute
     * @throws MissingMandatoryFieldException
     *             Thrown when the given input is invalid.
     * @throws ProfileNotFoundException
     *             Thrown when no profile found with given ID/Name.
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    T getProfileForImport(T profile) throws CANotFoundException, InvalidProfileException, InvalidProfileAttributeException,
            MissingMandatoryFieldException, ProfileNotFoundException, ProfileServiceException;

    /**
     * This method is used for retrieving the profiles in bulk which are used for import profiles operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @param profileType
     * @return {@link java.util.List} of {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile} that are retrieved from DB.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             Thrown when any internal error occurs in system.
     */
    Profiles getProfilesForImport(ProfileType profileType) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

}
