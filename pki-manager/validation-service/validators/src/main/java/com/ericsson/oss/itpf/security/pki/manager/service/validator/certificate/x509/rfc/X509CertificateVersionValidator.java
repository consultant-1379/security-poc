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
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class validates certificate's Version number
 * 
 * @author tcsramc
 *
 */
public class X509CertificateVersionValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateVersion(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateVersion(final String caName, final X509Certificate x509Certificate) throws UnSupportedCertificateVersion {
        logger.debug("Validate x509 certificate version for CA {}", caName, "{} ", x509Certificate.getVersion());
        if (x509Certificate.getVersion() != Constants.CERTIFICATE_VERSION_V3) {
            logger.error(ErrorMessages.INVALID_CERTIFICATE_VERSION + " for CA {}", caName);
            throw new UnSupportedCertificateVersion(ErrorMessages.INVALID_CERTIFICATE_VERSION);
        }
    }
}
