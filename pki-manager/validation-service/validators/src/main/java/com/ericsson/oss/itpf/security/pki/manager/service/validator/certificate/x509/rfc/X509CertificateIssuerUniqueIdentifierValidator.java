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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate CertificateIssuerUniqueIdentifier for the importedcertificate.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateIssuerUniqueIdentifierValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateIssuerUniqueId(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateIssuerUniqueId(final String caName, final X509Certificate x509Certificate) throws CertificateExtensionException {

        logger.debug("Validating X509Certificate CertificateIssuerUniqueId for CA Name{} ", caName, "{}", x509Certificate.getIssuerUniqueID());
        final int certificateVersion = x509Certificate.getVersion();
        if (x509Certificate.getIssuerUniqueID() != null) {
            if (!(certificateVersion == Constants.CERTIFICATE_VERSION_V2 || certificateVersion == Constants.CERTIFICATE_VERSION_V3)) {
                logger.error(ErrorMessages.ISSUER_UNIQUE_IDENTIFIER_IS_NOT_ALLOWED, " for CA {} ", caName);
                throw new CertificateExtensionException(ErrorMessages.ISSUER_UNIQUE_IDENTIFIER_IS_NOT_ALLOWED);
            }
        }

    }

}
