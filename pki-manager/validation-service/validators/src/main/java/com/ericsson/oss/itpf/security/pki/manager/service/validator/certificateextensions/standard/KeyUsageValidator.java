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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;

/**
 * This class validates KeyUsage extension. Critical must be marked true.
 * <p>
 * For CA, KeyCertSign and CRLSign keyUsagetypes are mandatory.
 * </p>
 * <p>
 * For end entity, at least one key usage type must be specified
 * </p>
 * <p>
 * KeyCertSign, CRLSign key usage types cannot be given for end entities.
 * </p>
 * 
 */
@CertificateExtensionsQualifier(CertificateExtensionType.KEY_USAGE)
public class KeyUsageValidator extends StandardExtensionValidator {

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws MissingMandatoryFieldException, InvalidKeyUsageExtension {
        validateKeyUsage((KeyUsage) certificateExtension, isProfileForCAEntity);
    }

    /**
     * This method validates the key usage attributes provided in certificate profile create/update request
     * 
     * @param keyUsage
     *            key usage object
     * @param isCAEntity
     *            attribute which indicates whether the profile is for CA or not
     */
    private void validateKeyUsage(final KeyUsage keyUsage, final boolean isProfileForCAEntity) throws MissingMandatoryFieldException, InvalidKeyUsageExtension {
        logger.debug("Validating KeyUsage in CertificateProfile{}", keyUsage);

        if (!isCertificateExtensionCritical(keyUsage)) {
            logger.error("For KeyUsage extension, critical must be true!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.KEY_USAGE + ProfileServiceErrorCodes.CRITICAL_MUST_BE_TRUE);
        }

        if (isProfileForCAEntity) {

            if (keyUsage == null) {
                logger.error("For CA, KeyUsage must be specified!");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_KEY_USAGE);
            }

            final List<KeyUsageType> keyUsageTypes = keyUsage.getSupportedKeyUsageTypes();
            validateKeyUsageTypesForCAProfile(keyUsageTypes);
        } else {

            if (keyUsage != null) {
                final List<KeyUsageType> keyUsageTypes = keyUsage.getSupportedKeyUsageTypes();
                validateKeyUsageTypesForEndEntityProfile(keyUsageTypes);
            }

        }
    }

    /**
     * @param keyUsageTypes
     */
    private void validateKeyUsageTypesForCAProfile(final List<KeyUsageType> keyUsageTypes) throws InvalidKeyUsageExtension {

        if (ValidationUtils.isNullOrEmpty(keyUsageTypes)) {
            logger.error("For CA, KeyCertSign and CRLSign keyUsagetypes are mandatory!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.CA_INVALID_KEY_USAGE_TYPE);
        }

        if (!keyUsageTypes.contains(KeyUsageType.KEY_CERT_SIGN)) {
            logger.error("For CA, KeyCertSign keyUsagetype is mandatory!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_KEY_CERT_SIGN);
        }

        if (!keyUsageTypes.contains(KeyUsageType.CRL_SIGN)) {
            logger.error("For CA, CRLSign keyUsagetype is mandatory!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_CRL_SIGN);
        }
    }

    /**
     * @param keyUsageTypes
     */
    private void validateKeyUsageTypesForEndEntityProfile(final List<KeyUsageType> keyUsageTypes) throws InvalidKeyUsageExtension {

        if (ValidationUtils.isNullOrEmpty(keyUsageTypes)) {
            logger.error("For End Entity, atleast 1 keyUsageType must be specified!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.INVALID_KEY_USAGE_TYPE);
        }

        if (keyUsageTypes.contains(KeyUsageType.KEY_CERT_SIGN)) {
            logger.error("End Entity cannot have KeyCertSign as keyUsageType!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_END_ENTITY + ProfileServiceErrorCodes.NOT_REQUIRED_KEY_CERT_SIGN);
        }

        if (keyUsageTypes.contains(KeyUsageType.CRL_SIGN)) {
            logger.error("End Entity cannot have CRLSign as keyUsageType!");
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_END_ENTITY + ProfileServiceErrorCodes.NOT_REQUIRED_CRL_SIGN);
        }
    }
}
