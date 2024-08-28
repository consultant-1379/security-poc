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
package com.ericsson.oss.itpf.security.pki.manager.common.enums;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;

/**
 * Used in case of validating CertificateExtensions given as part of Certificate Profile
 * 
 */
public enum CertificateExtensionType {

    BASIC_CONSTRAINTS("BasicConstraints"), AUTHORITY_INFORMATION_ACCESS("AuthorityInformationAccess"), AUTHORITY_KEY_IDENTIFIER("AuthorityKeyIdentifier"), SUBJECT_KEY_IDENTIFIER(
            "SubjectKeyIdentifier"), SUBJECT_ALT_NAME("SubjectAltName"), KEY_USAGE("KeyUsage"), EXTENDED_KEY_USAGE("ExtendedKeyUsage"), CRL_DISTRIBUTION_POINTS("CRLDistributionPoints");

    private final String name;

    private CertificateExtensionType(final String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }

    public static CertificateExtensionType getCertificateExtensionType(final String name) {
        for (final CertificateExtensionType certificateExtensionType : CertificateExtensionType.values()) {
            if (certificateExtensionType.getName().equals(name)) {
                return certificateExtensionType;
            }
        }

        throw new CertificateExtensionException(ProfileServiceErrorCodes.INVALID_EXTENSIONS_FOUND);
    }

    @Override
    public String toString() {
        return super.toString();
    }
}