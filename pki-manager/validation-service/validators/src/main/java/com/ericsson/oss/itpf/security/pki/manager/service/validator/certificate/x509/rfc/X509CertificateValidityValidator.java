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

import java.security.cert.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate Imported Certificate Validity.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateValidityValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {

        validateCertificateValidity(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateValidity(final String caName, final X509Certificate x509Certificate) throws ExpiredCertificateException {
        logger.debug("Validating X509Certificate Validity for CA {} not BeforeDate is {}  NotAfter Date is {}", caName, x509Certificate.getNotBefore(), x509Certificate.getNotAfter());
        try {
            x509Certificate.checkValidity();
        } catch (final CertificateNotYetValidException | CertificateExpiredException exception) {
            logger.debug(ErrorMessages.CERTIFICATE_EXPIRED, " for CA {} ", caName, exception);
            logger.error(ErrorMessages.CERTIFICATE_EXPIRED, " for CA {} ", caName);
            throw new ExpiredCertificateException(ErrorMessages.CERTIFICATE_EXPIRED);
        }
    }
}
