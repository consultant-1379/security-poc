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

package com.ericsson.oss.itpf.security.pki.manager.validation.service.profile;

import java.util.LinkedList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.BaseValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/**
 * This class is used to get the respective validators to validate a certificate profile.
 */
@ServiceQualifier(ItemType.CERTIFICATE_PROFILE)
public class CertificateProfileValidationService extends BaseValidationService<CertificateProfile> {

    @Inject
    Logger logger;

    @Inject
    CreateCertificateProfileNameValidator createCertificateProfileNameValidator;

    @Inject
    UpdateCertificateProfileNameValidator updateCertificateProfileNameValidator;

    @Inject
    CertificateVersionValidator certificateVersionValidator;

    @Inject
    CertificateValidityValidator certificateValidityValidator;

    @Inject
    CertificateProfileSignatureAlgorithmValidator certificateProfileSignatureAlgorithmValidator;

    @Inject
    CertificateProfileKeyGenerationAlgorithmValidator certificateProfileKeyGenerationAlgorithmValidator;

    @Inject
    IssuerUniqueIdentifierValidator certificateProfileIssuerUniqueIdentifierValidator;

    @Inject
    SkewCertificateTimeValidator certificateProfileSkewCertificateTimeValidator;

    @Inject
    SubjectCapabilitiesValidator certificateProfileSubjectCapabilitiesValidator;

    @Inject
    CertificateProfileExtensionsValidator certificateProfileCertificateExtensionsValidator;

    @Inject
    CAIssuerValidator caIssuerValidator;

    @Inject
    NonCAIssuerValidator nonCAIssuerValidator;

    //Discussed with PO, Profile validity is not required at this movement

    @Override
    public List<CommonValidator<CertificateProfile>> getValidators(final ValidateItem validateItem) {
        final List<CommonValidator<CertificateProfile>> certificateProfileValidators = new LinkedList<CommonValidator<CertificateProfile>>();
        final CertificateProfile certificateProfile = (CertificateProfile) validateItem.getItem();

        certificateProfileValidators.add(getProfileNameValidator(validateItem.getOperationType()));
        certificateProfileValidators.add(certificateVersionValidator);
        certificateProfileValidators.add(certificateValidityValidator);
        certificateProfileValidators.add(getIssuerValidator(certificateProfile.isForCAEntity()));
        certificateProfileValidators.add(certificateProfileSignatureAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileKeyGenerationAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileIssuerUniqueIdentifierValidator);
        certificateProfileValidators.add(certificateProfileCertificateExtensionsValidator);
        certificateProfileValidators.add(certificateProfileSkewCertificateTimeValidator);
        certificateProfileValidators.add(certificateProfileSubjectCapabilitiesValidator);
        return certificateProfileValidators;
    }

    private CommonValidator<CertificateProfile> getIssuerValidator(final boolean isCAEntity) {
        CommonValidator<CertificateProfile> validator = null;
        if (isCAEntity) {
            validator = caIssuerValidator;
        } else {
            validator = nonCAIssuerValidator;
        }
        return validator;
    }

    private CommonValidator<CertificateProfile> getProfileNameValidator(final OperationType operationType) {
        CommonValidator<CertificateProfile> validator = null;
        switch (operationType) {
        case CREATE:
            validator = createCertificateProfileNameValidator;
            break;
        case UPDATE:
            validator = updateCertificateProfileNameValidator;
            break;
        default:
            logger.error("Invalid Operation Type {}", operationType);
            throw new IllegalArgumentException("Invalid Operation Type " + operationType);
        }
        return validator;
    }

}
