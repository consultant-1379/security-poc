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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.privateinternet.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard.*;



/**
 * Certificate Extension Validator Factory used to get the instance of proper Certificate Extension Validator out of
 * <ul>
 * <li>{@link AuthorityInformationAccessValidator}
 * <li>
 * <li>{@link AuthorityKeyIdentifierValidator}</li>
 * <li>{@link BasicConstraintsValidator}</li>
 * <li>{@link CRLDistributionPointValidator}</li>
 * <li>{@link ExtendedKeyUsageValidator}</li>
 * <li>{@link KeyUsageValidator}</li>
 * <li>{@link SubjectKeyIdentifierValidator}</li>
 * <li>{@link SubjectAltNameExtensionValidator}</li>
 * </ul>
 *
 *
 */
public class CertificateExtensionValidatorFactory {

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.AUTHORITY_INFORMATION_ACCESS)
    CertificateExtensionValidator authorityInformationAccessValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER)
    CertificateExtensionValidator authorityKeyIdentifierValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.BASIC_CONSTRAINTS)
    CertificateExtensionValidator basicConstraintsValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.CRL_DISTRIBUTION_POINTS)
    CertificateExtensionValidator cRLDistributionPointValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.EXTENDED_KEY_USAGE)
    CertificateExtensionValidator extendedKeyUsageValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.KEY_USAGE)
    CertificateExtensionValidator keyUsageValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER)
    CertificateExtensionValidator subjectKeyIdentifierValidator;

    @Inject
    @CertificateExtensionsQualifier(CertificateExtensionType.SUBJECT_ALT_NAME)
    CertificateExtensionValidator subjectAltNameExtensionValidator;

    /**
     * The method to get the appropriate {@link CertificateExtensionValidator} instance based on {@link CertificateExtensionType}.
     *
     * @param certificateExtensionType
     * @return Instance of {@link CertificateExtensionValidator}
     */
    public CertificateExtensionValidator getCertificateExtensionValidator(final CertificateExtensionType certificateExtensionType) {
        CertificateExtensionValidator certificateExtensionValidator = null;

        switch (certificateExtensionType) {

        case AUTHORITY_INFORMATION_ACCESS:
            certificateExtensionValidator = authorityInformationAccessValidator;
            break;
        case AUTHORITY_KEY_IDENTIFIER:
            certificateExtensionValidator = authorityKeyIdentifierValidator;
            break;
        case BASIC_CONSTRAINTS:
            certificateExtensionValidator = basicConstraintsValidator;
            break;
        case CRL_DISTRIBUTION_POINTS:
            certificateExtensionValidator = cRLDistributionPointValidator;
            break;
        case EXTENDED_KEY_USAGE:
            certificateExtensionValidator = extendedKeyUsageValidator;
            break;
        case KEY_USAGE:
            certificateExtensionValidator = keyUsageValidator;
            break;
        case SUBJECT_KEY_IDENTIFIER:
            certificateExtensionValidator = subjectKeyIdentifierValidator;
            break;
        case SUBJECT_ALT_NAME:
            certificateExtensionValidator = subjectAltNameExtensionValidator;
            break;
        default:
            throw new CertificateExtensionException(ProfileServiceErrorCodes.UNSUPPORTED_CERTIFICATE_EXTENSION);
        }

        return certificateExtensionValidator;
    }
}
