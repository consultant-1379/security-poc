/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.validation.service.certificate;

import java.util.*;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/**
 * This class is used to fetch all the validators based on the user request.
 * 
 * @author tcsramc
 *
 */
@SuppressWarnings("PMD.TooManyFields")
@ServiceQualifier(ItemType.X509CERTIFICATE)
public class X509CertificateValidationService extends CertificateValidationService<CACertificateValidationInfo> {

    @Inject
    X509CertificateValidityValidator x509CertificateValidityValidator;

    @Inject
    X509CertificateExtensionValidator x509CertificateExtensionValidator;

    @Inject
    X509CertificateBasicConstraintsValidator x509CertificateBasicConstraintsValidator;

    @Inject
    X509CertificateCRLValidator x509CertificateCRLValidator;

    @Inject
    X509CertificateIssuerNameValidator x509CertificateIssuerNameValidator;

    @Inject
    X509CertificateKeyUsageValidator x509CertificateKeyUsageValidator;

    @Inject
    X509CertificateSerialNumberValidator x509CertificateSerialNumberValidator;

    @Inject
    X509CertificateSignatureValidator x509CertificateSignatureValidator;

    @Inject
    X509CertificateSubjectAltNameValidator x509CertificateSubjectAltNameValidator;

    @Inject
    X509CertificateSubjectKeyIdentifierValidator x509CertificateSubjectKeyIdentifierValidator;

    @Inject
    X509CertificateVersionValidator x509CertificateVersionValidator;

    @Inject
    X509CertificateAuthorityInformationAccessValidator x509CertificateAuthorityInformationAccessValidator;

    @Inject
    X509CertificateIssuerUniqueIdentifierValidator x509CertificateIssuerUniqueIdentifierValidator;

    @Inject
    X509CertificateSubjectUniqueIdentifierValidator x509CertificateSubjectUniqueIdentifierValidator;

    @Inject
    X509CertificateAuthorityKeyIdentifierValidator x509CertificateAuthorityKeyIdentifierValidator;

    @Inject
    X509CertificateExtendedKeyUsageValidator x509CertificateExtendedKeyUsageValidator;

    @Inject
    X509CertificateCRLDistrbutionpointValidator x509CertificateCRLDistrbutionPointValidator;

    @Inject
    X509CertificateSignatureAlgorithmValidator x509CertificateSignatureAlgorithmValidator;

    @Inject
    X509CertificateSearchValidator x509CertificateSearchValidator;

    @Inject
    CertificateGenerationInfoValidator certificateGenerationInfoValidator;

    @Inject
    AuthorityKeyIdentifierValidator authorityKeyIdentifierValidator;

    @Inject
    BasicConstraintsValidator basicConstraintsValidator;

    @Inject
    ExtendedKeyUsageValidator extendedKeyUsageValidator;

    @Inject
    KeyUsageValidator keyUsageValidator;

    @Inject
    SubjectAltNameValidator subjectAltNameValidator;

    @Inject
    SubjectAndPublicKeyValidator subjectAndPublicKeyValidator;

    @Inject
    SubjectKeyIdentifierValidator subjectKeyIdentifierValidator;

    /**
     * This method is used to get validators for corresponding Validation Service.
     *
     * @param validateItem
     *            Validate item object.
     *
     */
    @Override
    public List<CommonValidator<CACertificateValidationInfo>> getValidators(final ValidateItem validateItem) {

        final List<CommonValidator<CACertificateValidationInfo>> certificateValidators = new LinkedList<CommonValidator<CACertificateValidationInfo>>();

        final CACertificateValidationInfo cACertificateValidationInfo = (CACertificateValidationInfo) validateItem.getItem();
        final boolean isForceEnabled = cACertificateValidationInfo.isForceImport();

        final boolean isSkipOptionalTests = validateItem.isSkipOptionalTests();

        certificateValidators.add(x509CertificateSearchValidator);
        certificateValidators.add(authorityKeyIdentifierValidator);
        certificateValidators.add(subjectAndPublicKeyValidator);
        certificateValidators.add(x509CertificateValidityValidator);
        

        if (isSkipOptionalTests) {
            certificateValidators.addAll(getRFCValidators());
        }
        if (!isForceEnabled) {
            certificateValidators.addAll(getForceOptionValidators());
        }

        return certificateValidators;
    }

    private List<CommonValidator<CACertificateValidationInfo>> getForceOptionValidators() {
        final List<CommonValidator<CACertificateValidationInfo>> forceOptionValidators = new ArrayList<CommonValidator<CACertificateValidationInfo>>();
        forceOptionValidators.add(basicConstraintsValidator);
        forceOptionValidators.add(certificateGenerationInfoValidator);
        forceOptionValidators.add(extendedKeyUsageValidator);
        forceOptionValidators.add(keyUsageValidator);
        forceOptionValidators.add(subjectAltNameValidator);
        forceOptionValidators.add(subjectKeyIdentifierValidator);
        return forceOptionValidators;
    }

    private List<CommonValidator<CACertificateValidationInfo>> getRFCValidators() {

        final List<CommonValidator<CACertificateValidationInfo>> rfcValidators = new ArrayList<CommonValidator<CACertificateValidationInfo>>();
        rfcValidators.add(x509CertificateVersionValidator);
        rfcValidators.add(x509CertificateSerialNumberValidator);
        rfcValidators.add(x509CertificateSignatureAlgorithmValidator);
        rfcValidators.add(x509CertificateSignatureValidator);
        rfcValidators.add(x509CertificateIssuerNameValidator);
        rfcValidators.add(x509CertificateExtensionValidator);
        rfcValidators.add(x509CertificateBasicConstraintsValidator);
        rfcValidators.add(x509CertificateKeyUsageValidator);
        rfcValidators.add(x509CertificateSubjectAltNameValidator);
        rfcValidators.add(x509CertificateSubjectKeyIdentifierValidator);
        rfcValidators.add(x509CertificateAuthorityInformationAccessValidator);
        rfcValidators.add(x509CertificateAuthorityKeyIdentifierValidator);
        rfcValidators.add(x509CertificateCRLValidator);
        rfcValidators.add(x509CertificateCRLDistrbutionPointValidator);
        rfcValidators.add(x509CertificateIssuerUniqueIdentifierValidator);
        rfcValidators.add(x509CertificateSubjectUniqueIdentifierValidator);
        rfcValidators.add(x509CertificateExtendedKeyUsageValidator);
        return rfcValidators;
    }
}
