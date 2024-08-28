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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;

/**
 * This class validates keyusage present in {@link EntityProfile}.
 *
 * @author tcsvmeg
 *
 */
public class KeyUsageExtensionValidator implements CommonValidator<EntityProfile> {

    @Inject
    Logger logger;

    @Inject
    ProfilePersistenceHandlerFactory profilePersistenceHandlerFactory;

    @Inject
    CommonProfileHelper commonProfileHelper;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common. CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final EntityProfile entityProfile) throws ValidationException {
        logger.debug("validating  in entity profile {}", entityProfile.getName());

        validateKeyUsageExtension(entityProfile);
    }

    private void validateKeyUsageExtension(final EntityProfile entityProfile) throws MissingMandatoryFieldException, InvalidKeyUsageExtension {

        final String certificateProfileName = entityProfile.getCertificateProfile().getName();
        final CertificateProfile certificateProfile = commonProfileHelper.getCertificateProfile(certificateProfileName);

        final boolean isCAEntity = certificateProfile.isForCAEntity();
        final List<CertificateExtension> certificateExtensions = commonProfileHelper.extractCertificateExtensions(certificateProfile);

        final List<KeyUsageType> entityProfileKeyUsageTypes = commonProfileHelper.getEntityProfileKeyUsageExtension(entityProfile.getKeyUsageExtension());
        final List<KeyUsageType> certificateProfileKeyUsageTypes = commonProfileHelper.getCertificateProfileKeyUsageExtension(certificateExtensions);

        validateKeyUsage(certificateProfileKeyUsageTypes, entityProfileKeyUsageTypes, isCAEntity);
    }

    private void validateKeyUsage(final List<KeyUsageType> certificateProfileKeyUsageTypes, final List<KeyUsageType> entityProfileKeyUsageTypes, final boolean isCAEntity)
            throws MissingMandatoryFieldException, InvalidKeyUsageExtension {
        if (ValidationUtils.isNullOrEmpty(entityProfileKeyUsageTypes) && isCAEntity) {
            logger.error("KeyUsageType  can not be empty in the Entity Profile");
            throw new MissingMandatoryFieldException("For a Entity Profile associated with a Certificate Authority Profile a Key Usage type is required");
        }
        if (isCAEntity) {
            if (!(entityProfileKeyUsageTypes.contains(KeyUsageType.CRL_SIGN) && entityProfileKeyUsageTypes.contains(KeyUsageType.KEY_CERT_SIGN))) {
                logger.error("For CA KeyCertSign,cRLSign key usage types are mandatory!");
                throw new InvalidKeyUsageExtension("For CA KeyCertSign,cRLSign key usage types are mandatory!");
            }

        }
        if (!isCAEntity) {
            if (ValidationUtils.isNullOrEmpty(certificateProfileKeyUsageTypes) && !ValidationUtils.isNullOrEmpty(entityProfileKeyUsageTypes)) {
                logger.error("KeyUsageType  is not supported in Certificate Profile");
                throw new InvalidKeyUsageExtension("KeyUsageType  is not supported in Certificate Profile");
            }
        }

        if (!ValidationUtils.isNullOrEmpty(entityProfileKeyUsageTypes) && !ValidationUtils.isNullOrEmpty(certificateProfileKeyUsageTypes)) {
            isKeyUsageSubSet(certificateProfileKeyUsageTypes, entityProfileKeyUsageTypes);
        }
    }

    private void isKeyUsageSubSet(final List<KeyUsageType> certificateProfileKeyUsageTypes, final List<KeyUsageType> entityProfileKeyUsageTypes) throws InvalidKeyUsageExtension {

        for (final KeyUsageType keyUsageType : entityProfileKeyUsageTypes) {

            if (!certificateProfileKeyUsageTypes.contains(keyUsageType)) {
                logger.error("KeyUsageType::", keyUsageType, " is not present in Certificate Profile Extension attributes");
                throw new InvalidKeyUsageExtension("Given Keyusage type " + keyUsageType + " is not present in Certificate Profile Extensions");
            }
        }
    }
}