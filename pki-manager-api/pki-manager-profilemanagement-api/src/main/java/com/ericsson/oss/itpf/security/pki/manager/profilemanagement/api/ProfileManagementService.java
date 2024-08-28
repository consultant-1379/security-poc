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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.Profiles;

/**
 * This is an interface for profile management service and provides API's for below operations.
 * <ul>
 * <li>Importing all profiles in bulk manner.</li>
 * <li>Exporting all profiles.</li>
 * <li>CRUD of different profiles.</li>
 * </ul>
 */
@EService
@Remote
public interface ProfileManagementService {
    /**
     * Import all profiles in bulk manner. XML file should be validated using provided XSD schema and map the XML file to Profiles object containing list of TrustProfile, EntityProfile and
     * CertificateProfile.
     * 
     * @param profiles
     *            Profiles Object containing list of trust/entity/certificate profiles.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given signature or key generation algorithms are not found or inactive.
     * @throws CANotFoundException
     *             thrown when given CAs in trustProfile doesn't exists or in revoked state
     * @throws CertificateExtensionException
     *             thrown when any of the Certificate Extensions holds invalid values.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws InvalidCAException
     *             thrown when inactive CA is mapped as issuer in certificate profile.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when any of the profile attribute is not valid.
     * @throws InvalidSubjectException
     *             thrown when invalid subject values are given
     * @throws MissingMandatoryFieldException
     *             thrown when mandatory field input is not provided.
     * @throws ProfileAlreadyExistsException
     *             thrown when profile already exists with given updated name.
     * @throws ProfileNotFoundException
     *             thrown when given CertificateProfile or TrustProfile inside Entity Profile doesn't exists or in inactive state.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws UnSupportedCertificateVersion
     *             thrown when invalid certificate version is given in certificate profile.
     */
    void importProfiles(Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion;

    /**
     * Export profiles in bulk manner. It returns all the profiles of specified type in Profiles Object.
     * 
     * @param profileType
     *            Profile Type specifies the type of profiles to be exported.It accepts values trustprofile, entityprofile, certificateprofile and all.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles or All.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    Profiles exportProfiles(ProfileType... profileType) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

    /**
     * Export profiles in bulk manner. It returns all the profiles of specified type in Profiles Object which is used for Import Profiles operation.
     *
     * @param profileType
     *            Profile Type specifies the type of profiles to be exported.It accepts values trustprofile, entityprofile, certificateprofile and
     *            all.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles or All.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    Profiles exportProfilesForImport(ProfileType... profileType) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;

    /**
     * Bulk update of Profiles of any type using XML. XML file should be validated using provided XSD schema and map the XML file to Profiles object containing list of TrustProfile, EntityProfile and
     * CertificateProfile.
     * 
     * @param profiles
     *            Profiles Object containing list of updated trust/entity/certificate profiles.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given signature or key generation algorithms are not found or inactive.
     * @throws CANotFoundException
     *             thrown when given CAs in trustProfile doesn't exists or in revoked state
     * @throws CertificateExtensionException
     *             thrown when any of the Certificate Extensions holds invalid values.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws InvalidCAException
     *             thrown when inactive CA is mapped as issuer in certificate profile.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when any of the profile attribute is not valid.
     * @throws InvalidSubjectException
     *             thrown when invalid subject values are given
     * @throws MissingMandatoryFieldException
     *             thrown when mandatory field input is not provided.
     * @throws ProfileAlreadyExistsException
     *             thrown when profile already exists with given updated name.
     * @throws ProfileNotFoundException
     *             thrown when given CertificateProfile or TrustProfile inside Entity Profile doesn't exists or in inactive state.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws UnSupportedCertificateVersion
     *             thrown when invalid certificate version is given in certificate profile.
     */
    void updateProfiles(Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion;

    /**
     * Bulk deletion of profiles of any type based on id or name.To delete any profile, id/name and profileType should be set in the list of Profile objects and sent as argument.
     * 
     * @param profiles
     *            Contains list of TrustProfiles,EntityProfiles and CertificateProfiles with id/name filled.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileInUseException
     *             thrown when given profile to be deleted is in use by other profiles/entities.
     * @throws ProfileNotFoundException
     *             thrown when given CertificateProfile or TrustProfile inside Entity Profile doesn't exists or in inactive state.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    void deleteProfiles(Profiles profiles) throws InvalidProfileException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException;

    /**
     * Create a Trust Profile or Certificate Profile or Entity Profile.
     * 
     * @param Object
     *            of TrustProfile/CertificateProfile/EntityProfile.
     * @return Created profile object.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given signature or key generation algorithms are not found or inactive.
     * @throws CANotFoundException
     *             thrown when given CAs in trustProfile doesn't exists or in revoked state
     * @throws CertificateExtensionException
     *             thrown when any of the Certificate Extensions holds invalid values.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws InvalidCAException
     *             thrown when inactive CA is mapped as issuer in certificate profile.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when any of the profile attribute is not valid.
     * @throws InvalidSubjectException
     *             thrown when invalid subject values are given
     * @throws MissingMandatoryFieldException
     *             thrown when mandatory field input is not provided.
     * @throws ProfileAlreadyExistsException
     *             thrown when trying to create a profile that already exists.
     * @throws ProfileNotFoundException
     *             thrown when given CertificateProfile or TrustProfile inside Entity Profile doesn't exists or in inactive state.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws UnSupportedCertificateVersion
     *             thrown when invalid certificate version is given in certificate profile.
     */
    <T extends AbstractProfile> T createProfile(T profile) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion;

    /**
     * Update a Trust Profile or Certificate Profile or Entity Profile.
     * 
     * @param Object
     *            of TrustProfile/CertificateProfile/EntityProfile with updated values.
     * @return Returns updated object of TrustProfile/CertificateProfile/EntityProfile.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given signature or key generation algorithms are not found or inactive.
     * @throws CANotFoundException
     *             thrown when given CAs in trustProfile doesn't exists or in revoked state
     * @throws CertificateExtensionException
     *             thrown when any of the Certificate Extensions holds invalid values.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws InvalidCAException
     *             thrown when inactive CA is mapped as issuer in certificate profile.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when any of the profile attribute is not valid.
     * @throws InvalidSubjectException
     *             thrown when invalid subject values are given
     * @throws MissingMandatoryFieldException
     *             thrown when mandatory field input is not provided.
     * @throws ProfileAlreadyExistsException
     *             thrown when profile already exists with given updated name.
     * @throws ProfileNotFoundException
     *             thrown when given CertificateProfile or TrustProfile inside Entity Profile doesn't exists or in inactive state.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws UnSupportedCertificateVersion
     *             thrown when invalid certificate version is given in certificate profile.
     */
    <T extends AbstractProfile> T updateProfile(T profile) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion;

    /**
     * Get Profile based on Id/name.
     * 
     * @param profile
     *            Object of TrustProfile/CertificateProfile/EntityProfile with id or name set.
     * @return Returns object of TrustProfile/CertificateProfile/EntityProfile. if found or else throws ProfileServiceException.
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when given profile name is not in a valid format.
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws MissingMandatoryFieldException
     *             thrown when the provided input is invalid.
     */
    <T extends AbstractProfile> T getProfile(T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException,
            MissingMandatoryFieldException;

    /**
     * Get Profile based on Id/name which is used for Profile Import/update operation.
     *
     * @param profile
     *            Object of TrustProfile/CertificateProfile/EntityProfile with id or name set.
     * @return Returns object of TrustProfile/CertificateProfile/EntityProfile. if found or else throws ProfileServiceException.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when given profile name is not in a valid format.
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws MissingMandatoryFieldException
     *             thrown when the provided input is invalid.
     */
    <T extends AbstractProfile> T getProfileForImport(T profile)
            throws InvalidProfileException, InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException, MissingMandatoryFieldException;

    /**
     * Get Profiles based on entityCategory.
     * 
     * @param EntityCategory
     *            Object of EntityCategory with name/id.
     * @return Returns list of entity profiles, if found or else throws ProfileServiceException.
     * 
     * @throws EntityCategoryNotFoundException
     *             thrown when given category name not found.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when given profile name is not in a valid format.
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    List<EntityProfile> getProfilesByCategory(EntityCategory entityCategory) throws EntityCategoryNotFoundException, InvalidProfileException, InvalidProfileAttributeException,
            ProfileNotFoundException, ProfileServiceException;

    /**
     * Delete a profile based on Id/name.
     * 
     * <ul>
     * <li>Trust profile can only be deleted, if there are no mappings to any entity profile.</li>
     * <li>Certificate profile can only be deleted, if there are no mappings to any entity profile.</li>
     * <li>Entity profile can be deleted only if there are no mappings to any entity/caentity.</li>
     * </ul>
     * 
     * @param profile
     *            Object of TrustProfile/CertificateProfile/EntityProfile with id or name set.
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileInUseException
     *             thrown when given profile to be deleted is in use by other profiles/entities.
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * 
     */
    <T extends AbstractProfile> void deleteProfile(T profile) throws InvalidProfileException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException;

    /**
     * Method to check whether the given profile name is available or not, while creating profile through UI.
     * 
     * @param name
     *            Name to be verified for the availability.
     * @param profileType
     *            Type of profile in which name to be verified.
     * @return true if name is available or else false.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    <T extends AbstractProfile> boolean isProfileNameAvailable(String name, ProfileType profileType) throws InvalidProfileException, ProfileServiceException;

    /**
     * Get profiles that are active. It returns all active profiles of specified type in Profiles Object.
     * 
     * @param profileType
     *            Profile Type specifies the type of profiles to be exported.It accepts values trustprofile, entityprofile, certificateprofile and all.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles or All.
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    Profiles getActiveProfiles(ProfileType... profileType) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException;
}
