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
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;

/**
 * This class validates extended keyusage present in {@link EntityProfile}.
 *
 * @author tcsvmeg
 *
 */
public class ExtendedKeyUsageValidator implements CommonValidator<EntityProfile> {

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
        validateExtendedKeyUsage(entityProfile);
    }

    private void validateExtendedKeyUsage(final EntityProfile entityProfile) throws InvalidExtendedKeyUsageExtension {

        final String certificateProfileName = entityProfile.getCertificateProfile().getName();
        final CertificateProfile certificateProfile = commonProfileHelper.getCertificateProfile(certificateProfileName);

        final List<CertificateExtension> certificateExtensions = commonProfileHelper.extractCertificateExtensions(certificateProfile);

        final List<KeyPurposeId> entityProfileKeyPurposeIds = commonProfileHelper.getEntityProfileExtendedKeyUsageExtension(entityProfile.getExtendedKeyUsageExtension());
        final List<KeyPurposeId> certificateProfileKeyPurposeIds = commonProfileHelper.getCertificateProfileExtendedKeyUsageExtension(certificateExtensions);

        validateExtendedKeyUsage(certificateProfileKeyPurposeIds, entityProfileKeyPurposeIds);

    }

    private void validateExtendedKeyUsage(final List<KeyPurposeId> certificateProfileKeyPurposeIds, final List<KeyPurposeId> entityProfileKeyPurposeIds) throws InvalidExtendedKeyUsageExtension {
        if (ValidationUtils.isNullOrEmpty(certificateProfileKeyPurposeIds) && !ValidationUtils.isNullOrEmpty(entityProfileKeyPurposeIds)) {
            logger.error("Key Purpose ID List is empty in Certificate profile Extensions");
            throw new InvalidExtendedKeyUsageExtension(ProfileServiceErrorCodes.ERR_NO_KEY_PURPOSE_ID_VALUES_IN_DB);
        }

        if (!ValidationUtils.isNullOrEmpty(entityProfileKeyPurposeIds) && !ValidationUtils.isNullOrEmpty(certificateProfileKeyPurposeIds)) {
            isExtendedKeyUsageSubSet(certificateProfileKeyPurposeIds, entityProfileKeyPurposeIds);
        }
    }

    private void isExtendedKeyUsageSubSet(final List<KeyPurposeId> certificateProfileKeyPurposeIds, final List<KeyPurposeId> entityProfileKeyPurposeIds) throws InvalidExtendedKeyUsageExtension {
        for (final KeyPurposeId keyPurposeID : entityProfileKeyPurposeIds) {
            if (!certificateProfileKeyPurposeIds.contains(keyPurposeID)) {
                logger.error("KeyUsageType::", keyPurposeID, " is not present in Certificate Profile Extension attributes");
                throw new InvalidExtendedKeyUsageExtension("Unknown keyPurposeID is present in Certificate Profile Extensions");
            }
        }
    }
}