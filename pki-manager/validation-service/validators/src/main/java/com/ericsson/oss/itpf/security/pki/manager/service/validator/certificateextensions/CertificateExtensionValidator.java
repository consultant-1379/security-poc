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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * This interface is extended by {@link StandardExtensionvalidator} / {@link PrivateExtensionvalidator}
 *
 */
public interface CertificateExtensionValidator {
    /**
     * This method checks whether CertificateExtension values provided satisfies the desired criteria
     *
     * @param certificateExtension
     *            certificate extension object
     * @param isProfileForCAEntity
     * @param isCAEntity
     *            a boolean attribute which indicates the profile is for CA entity or not
     * @param issuerName
     *            name of the certificate issuer
     * @throws ProfileServiceException
     * @throws CertificateExtensionException
     * @throws MissingMandatoryFieldException
     * @throws InternalServiceException
     *             if any exception arises when fetching algorithms from database
     */
    void validate(final CertificateExtension certificateExtension, boolean isProfileForCAEntity, String issuerName) throws ProfileServiceException, CertificateExtensionException,
            MissingMandatoryFieldException;
}
