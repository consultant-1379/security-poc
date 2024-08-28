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

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.profile.ProfilePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;

/**
 * Helper class to get the certificate profile and its extensions.
 *
 * @author tcsvmeg
 *
 */
public class CommonProfileHelper {

    @Inject
    Logger logger;

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    /**
     * This method is used to get the certificate profile data.
     *
     * @param certificateProfileName
     * @return Certificate profile object
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when the given profile is not found in DB.
     */
    public CertificateProfile getCertificateProfile(final String certificateProfileName) throws ProfileServiceException, ProfileNotFoundException {

        CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName(certificateProfileName);

        final ProfilePersistenceHandler<CertificateProfile> certificateProfilePersistenceHandler = getPersistenceHandler(ProfileType.CERTIFICATE_PROFILE);

        certificateProfile = certificateProfilePersistenceHandler.getProfile(certificateProfile);
        return certificateProfile;
    }

    /**
     * This method is used to get list of certificate extensions.
     *
     * @param certificateProfile
     * @return List of Certificate extensions
     * @throws CertificateExtensionException
     *             thrown when certificate extension doesn't exist in certificate profile
     */
    public List<CertificateExtension> extractCertificateExtensions(final CertificateProfile certificateProfile) throws CertificateExtensionException {
        final CertificateExtensions certificateExtensions = certificateProfile.getCertificateExtensions();

        if (certificateExtensions == null) {
            logger.error("Certificate Extensions Does not exists  in Name:" + certificateProfile.getName());
            throw new CertificateExtensionException(ProfileServiceErrorCodes.ERR_NO_CERTIFICATEEXTENSIONS_FOUND + certificateProfile.getName());
        }

        return certificateExtensions.getCertificateExtensions();
    }

    /**
     * This method is used to get list of key usage types in keyusage extension of entity profile.
     *
     * @param keyUsageExtension
     * @return List of keyUsage types
     * @throws InvalidKeyUsageExtension
     *             thrown when the given keyUsage extension is invalid.
     */
    public List<KeyUsageType> getEntityProfileKeyUsageExtension(final KeyUsage keyUsageExtension) throws InvalidKeyUsageExtension {
        List<KeyUsageType> entityProfileKeyUsageTypes = null;

        if (keyUsageExtension != null) {
            if (!keyUsageExtension.isCritical()) {
                logger.error("For KeyUsage extension, critical must be true!");
                throw new InvalidKeyUsageExtension(Constants.KEY_USAGE + ProfileServiceErrorCodes.ERR_CRITICAL_MUST_BE_TRUE);
            }
            entityProfileKeyUsageTypes = keyUsageExtension.getSupportedKeyUsageTypes();
        }

        return entityProfileKeyUsageTypes;
    }

    /**
     * This method is used to get list of keyusage types in keyusage extension of certifcate profile.
     *
     * @param certificateExtensions
     *            List of certificate extensions
     * @return List of key usage types in certificate profile
     */
    public List<KeyUsageType> getCertificateProfileKeyUsageExtension(final List<CertificateExtension> certificateExtensions) {
        List<KeyUsageType> keyUsageTypes = null;
        final KeyUsage keyUsageExtension = (KeyUsage) extractCertificateExtension(certificateExtensions, KeyUsage.class);

        if (keyUsageExtension != null) {
            keyUsageTypes = keyUsageExtension.getSupportedKeyUsageTypes();
        }

        return keyUsageTypes;
    }

    /**
     * This method is used to get list of keypurposeId's in extended keyusage extension of entity profile.
     *
     * @param extendedKeyUsageExtension
     * @return List of keyPurposeId's
     */
    public List<KeyPurposeId> getEntityProfileExtendedKeyUsageExtension(final ExtendedKeyUsage extendedKeyUsageExtension) {
        List<KeyPurposeId> keyPurposeIds = null;

        if (extendedKeyUsageExtension != null) {
            keyPurposeIds = extendedKeyUsageExtension.getSupportedKeyPurposeIds();
        }

        return keyPurposeIds;
    }

    /**
     * This method is used to get list of keypurposeId's in extended keyusage extension of certifcate profile.
     *
     * @param certificateExtensions
     * @return List of KeyPurposeId's
     */
    public List<KeyPurposeId> getCertificateProfileExtendedKeyUsageExtension(final List<CertificateExtension> certificateExtensions) {
        List<KeyPurposeId> keyPurposeIds = null;
        final ExtendedKeyUsage extendedKeyUsage = extractCertificateExtension(certificateExtensions, ExtendedKeyUsage.class);

        if (extendedKeyUsage != null) {
            keyPurposeIds = extendedKeyUsage.getSupportedKeyPurposeIds();
        }

        return keyPurposeIds;
    }

    /**
     * This method is used to get the certificate extension.
     *
     * @param certificateExtensions
     *            List of certificate extensions
     * @param extensionClass
     * @return certificate extensions extracted
     */
    @SuppressWarnings("unchecked")
    public <T extends CertificateExtension> T extractCertificateExtension(final List<CertificateExtension> certificateExtensions, final Class<T> extensionClass) {
        T certificateExtensionExtracted = null;

        for (final CertificateExtension certificateExtension : certificateExtensions) {
            if (certificateExtension.getClass().equals(extensionClass)) {
                certificateExtensionExtracted = (T) certificateExtension;
                return certificateExtensionExtracted;
            }
        }

        return certificateExtensionExtracted;
    }

    /**
     *
     * @param profileType
     *            type of profile. In this case its trustprofile.
     * @return ProfilePersistenceHandler returns profilePersistenceHandler object.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors or service exception occurs.
     */
    @SuppressWarnings("unchecked")
    public <T extends AbstractProfile> ProfilePersistenceHandler<T> getPersistenceHandler(final ProfileType profileType) throws ProfileServiceException {
        return (ProfilePersistenceHandler<T>) profilePersistenceHandlerFactory.getProfilePersistenceHandler(profileType);
    }
}
