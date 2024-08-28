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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ProfileManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.ProfileManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;


/**
 * This class implements {@link ProfileManagementService}
 */
@Profiled
@Stateless
@EServiceQualifier("1.0.0")
public class ProfileManagementServiceBean implements ProfileManagementService {

    @Inject
    private ProfileManager profileManager;

    @Inject
    private ProfileManagementAuthorizationManager profileManagementAuthorization;

    @EServiceRef
    ValidationService validationService;

    @Inject
    ValidationServiceUtils validateServiceUtils;

    @Inject
    ContextUtility contextUtility;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

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
    @Override
    public void importProfiles(final Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.IMPORT);

        logger.debug("Importing Profiles in bulk");

        if (profiles.getTrustProfiles() != null) {
            for (final TrustProfile trustProfile : profiles.getTrustProfiles()) {
                createProfile(trustProfile);
            }
        }

        if (profiles.getCertificateProfiles() != null) {
            for (final CertificateProfile certificateProfile : profiles.getCertificateProfiles()) {
                createProfile(certificateProfile);
            }
        }

        if (profiles.getEntityProfiles() != null) {
            for (final EntityProfile entityProfile : profiles.getEntityProfiles()) {
                createProfile(entityProfile);
            }
        }

        logger.debug("Imported all profiles provided");
    }

    /**
     * Export profiles in bulk manner. It returns the profiles based on the ProfileType(CertificateProfile,TrustProfile,EntityProfile)
     * 
     * @param ProfileType
     *            ProfileType specifies the type of profiles to be exported.It accepts Variable argument values namely CertificateProfile, TrustProfile, EntityProfile.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles.
     * 
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public Profiles exportProfiles(final ProfileType... profileTypes) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);

        logger.debug("exportProfiles by type {} ", new Object[] { profileTypes });

        if (profileTypes.length == 0) {
            throw new IllegalArgumentException(ProfileServiceErrorCodes.NO_PROFILETYPE_PRESENT);
        }

        final Profiles profiles = profileManager.getProfiles(profileTypes);

        logger.debug("Exported profiles :: {}", profiles);
        return profiles;

    }

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
    @Override
    @ErrorLogAnnotation
    public <T extends AbstractProfile> T createProfile(final T profile) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException,
            InvalidCAException, InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileAlreadyExistsException, ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.CREATE);

        logger.debug("Creating profile of Type {} with Name {}", profile.getType(), profile.getName());

        final ValidateItem validateItem = validateServiceUtils.generateProfileValidateItem(profile.getType(), OperationType.CREATE, profile);
        validationService.validate(validateItem);

        final T createdProfile = profileManager.createProfile(profile);

        logger.debug("Created {} with ID: {}", profile.getType(), profile.getId());

        systemRecorder.recordEvent("PROFILEMANAGEMENT.CREATE_PROFILE", EventLevel.COARSE, " PKI ", " PKIManager ", " Profile [name = " + profile.getName() + ", type = " + profile.getType()
                + " ] created successfully");

        return createdProfile;
    }

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
    @Override
    @ErrorLogAnnotation
    public <T extends AbstractProfile> T updateProfile(final T profile) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException,
            InvalidCAException, InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileAlreadyExistsException, ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);

        validateModifiableStatus(profile);

        logger.debug("Updating profile of Type {} with Name {}", profile.getType(), profile.getName());

        final ValidateItem validateItem = validateServiceUtils.generateProfileValidateItem(profile.getType(), OperationType.UPDATE, profile);
        validationService.validate(validateItem);

        final T profileUpdated = (T) profileManager.updateProfile(profile);

        logger.debug("Updated {} with ID: {}", profile.getType(), profile.getId());

        systemRecorder.recordEvent("PROFILEMANAGEMENT.UPDATE_PROFILE", EventLevel.COARSE, " PKI ", " PKIManager ", " Profile [name = " + profile.getName() + ", type = " + profile.getType()
                + " ] updated successfully");

        return profileUpdated;
    }

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
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws MissingMandatoryFieldException
     *             thrown when the provided input is invalid.
     */
    @Override
    @ErrorLogAnnotation
    public <T extends AbstractProfile> T getProfile(final T profile) throws InvalidProfileException, InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException,
            MissingMandatoryFieldException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);

        logger.info("Fetching profile of Type {}", profile.getType());

        final T profileFound = (T) profileManager.getProfile(profile);

        logger.debug("Fetched {} with ID: {}", profile.getType(), profile.getId());
        return profileFound;
    }

    /**
     * Delete a profile based on Id/name.
     * <ul>
     * <li>Trust profile can only be deleted, if there are no mappings to any entity profile.</li>
     * <li>Certificate profile can only be deleted, if there are no mappings to any entity profile.</li>
     * <li>Entity profile can be deleted only if there are no mappings to any entity/caentity.</li>
     * </ul>
     * 
     * @param profile
     *            Object of TrustProfile/CertificateProfile/EntityProfile with id or name set.
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws ProfileInUseException
     *             thrown when given profile to be deleted is in use by other profiles/entities.
     */
    @Override
    @ErrorLogAnnotation
    public <T extends AbstractProfile> void deleteProfile(final T profile) throws InvalidProfileException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.DELETE);

        logger.debug("Deleting {}", profile.getType());

        profileManager.deleteProfile(profile);

        logger.debug("Deleted {}", profile.getType());

        systemRecorder.recordEvent("PROFILEMANAGEMENT.DELETE_PROFILE", EventLevel.COARSE, " PKI ", " PKIManager ", " Profile [name = " + profile.getName() + ", type = " + profile.getType()
                + " ] deleted successfully");

    }

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
    @Override
    @ErrorLogAnnotation
    public <T extends AbstractProfile> boolean isProfileNameAvailable(final String name, final ProfileType profileType) throws InvalidProfileException, ProfileServiceException {

        profileManagementAuthorization.authorizeIsProfileNameAvailable();

        logger.debug("checking name availability for {}", profileType);

        final boolean isAvailable = profileManager.isNameAvailable(name, profileType);

        logger.debug("Exiting: isProfileNameAvailable");

        return isAvailable;
    }

    /**
     * Bulk deletion of profiles of any type based on id or name.To delete any profile, id/name and profileType should be set in the list of Profile objects and sent as argument.
     * 
     * @param profiles
     *            Contains list of TrustProfiles,EntityProfiles and CertificateProfiles with id/name filled.
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileInUseException
     *             thrown when given profile to be deleted is in use by other profiles/entities.
     */
    @Override
    public void deleteProfiles(final Profiles profiles) throws InvalidProfileException, ProfileInUseException, ProfileNotFoundException, ProfileServiceException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.DELETE);

        logger.debug("Deleting Profiles in bulk");

        profileManager.deleteProfiles(profiles);

        logger.debug("Deleted all profiles provided");

    }

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
    @Override
    public void updateProfiles(final Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.UPDATE);

        logger.debug("Updating Profiles in bulk");

        validateProfiles(profiles);
        profileManager.updateProfiles(profiles);

        logger.debug("Updated all profiles provided");

    }

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
    @Override
    @ErrorLogAnnotation()
    public List<EntityProfile> getProfilesByCategory(final EntityCategory entityCategory) throws EntityCategoryNotFoundException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidProfileAttributeException, ProfileNotFoundException, ProfileServiceException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);

        profileManager.getEntityProfilesByCategory(entityCategory);
        return null;
    }

    /**
     * Get active profiles. It returns all active profiles of specified type in Profiles Object.
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
    @Override
    @ErrorLogAnnotation()
    public Profiles getActiveProfiles(final ProfileType... profileTypes) throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);

        logger.debug("export active profiles by type {} ", new Object[] { profileTypes });

        if (profileTypes.length == 0) {
            throw new IllegalArgumentException(ProfileServiceErrorCodes.NO_PROFILETYPE_PRESENT);
        }

        final Profiles profiles = profileManager.getActiveProfiles(profileTypes, true);

        logger.debug("Exported profiles :: {}", profiles);
        return profiles;
    }

    private void validateProfiles(final Profiles profiles) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException, InvalidCAException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion {

        if (profiles.getTrustProfiles() != null) {
            for (final TrustProfile trustProfile : profiles.getTrustProfiles()) {
                final ValidateItem validateItem = validateServiceUtils.generateProfileValidateItem(trustProfile.getType(), OperationType.UPDATE, trustProfile);
                validationService.validate(validateItem);
            }
        }

        if (profiles.getEntityProfiles() != null) {
            for (final EntityProfile entityProfile : profiles.getEntityProfiles()) {
                validateModifiableStatus(entityProfile);
                final ValidateItem validateItem = validateServiceUtils.generateProfileValidateItem(entityProfile.getType(), OperationType.UPDATE, entityProfile);
                validationService.validate(validateItem);
            }
        }

        if (profiles.getCertificateProfiles() != null) {
            for (final CertificateProfile certificateProfile : profiles.getCertificateProfiles()) {
                validateModifiableStatus(certificateProfile);
                final ValidateItem validateItem = validateServiceUtils.generateProfileValidateItem(certificateProfile.getType(), OperationType.UPDATE, certificateProfile);
                validationService.validate(validateItem);
            }
        }
    }

    private <T extends AbstractProfile> void validateModifiableStatus(final T profile) throws InvalidProfileException {

        if (!(contextUtility.isCredMOperation())) {
            if (profile.getType().equals(ProfileType.CERTIFICATE_PROFILE) || profile.getType().equals(ProfileType.ENTITY_PROFILE)) {
                logger.debug("Fetching modifiable status of profile with name {}" + profile.getName());

                final boolean isModifiable = profileManager.getModifiableStatus(profile);
                if (!isModifiable) {
                    logger.error("Profile Modifiable flag is disabled!!");
                    throw new InvalidProfileException(Constants.ERR_MODIFIABLE_PROFILE_FLAG);
                }
            }
        }
    }

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
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when no profile exists with given name/id.
     * @throws MissingMandatoryFieldException
     *             thrown when the provided input is invalid.
     */
    @Override
    public <T extends AbstractProfile> T getProfileForImport(final T profile) throws InvalidProfileException, InvalidProfileAttributeException,
            ProfileNotFoundException, ProfileServiceException, MissingMandatoryFieldException {

        profileManagementAuthorization.authorizeProfileOperations(ActionType.READ);

        logger.info("Fetching profile of Type {}", profile.getType());

        final T profileFound = (T) profileManager.getProfileForImport(profile);

        logger.debug("Fetched {} with ID: {}", profile.getType(), profile.getId());
        return profileFound;
    }

    /**
     * Export profiles in bulk manner. It returns the profiles based on the ProfileType(CertificateProfile,TrustProfile,EntityProfile)
     *
     * @param ProfileType
     *            ProfileType specifies the type of profiles to be exported.It accepts Variable argument values namely CertificateProfile,
     *            TrustProfile, EntityProfile.
     * @return Profiles object containing list of Certificate/Trust/Entity Profiles.
     *
     * @throws InvalidProfileException
     *             thrown when Invalid Profile Type other than Entity/Certificate/Trust Profile is provided
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public Profiles exportProfilesForImport(final ProfileType... profileTypes)
            throws InvalidProfileException, InvalidProfileAttributeException, ProfileServiceException {
        profileManagementAuthorization.authorizeProfileOperations(ActionType.EXPORT);

        logger.debug("exportProfiles by type {} ", new Object[] { profileTypes });

        if (profileTypes.length == 0) {
            throw new IllegalArgumentException(ProfileServiceErrorCodes.NO_PROFILETYPE_PRESENT);
        }

        final Profiles profiles = profileManager.getProfilesForImport(profileTypes);

        logger.debug("Exported profiles :: {}", profiles);
        return profiles;
    }
}