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
package com.ericsson.oss.itpf.security.pki.common.validator;

import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CertificateRevokedException;

/**
 * This class handles certificateRevocation validations.
 * 
 * @author tcsramc
 * 
 */
public class CertificateRevokeValidator {

    @Inject
    Logger logger;

    /**
     * This method is used to validate whether given certificate serial number is present in the cRL or not. returns true if the given certificate is on this CRL, false otherwise.
     * 
     * @param certificate
     *            to verify.
     * @throws CertificateRevocationException
     *             is thrown if certificate is revoked.
     */
    public void validate(final X509Certificate certificate, final X509CRL issuerCRL) throws CertificateRevokedException {
        if (issuerCRL != null) {
            if (issuerCRL.isRevoked(certificate)) {
                logger.error("Entity Certificate is Revoked, Serial Number: {}", certificate.getSerialNumber());
                throw new CertificateRevokedException(ErrorMessages.CERTIFICATE_REVOKED);
            }
        }
    }
}
