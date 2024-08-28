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

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class validates SerialNumber of X509Certificate as per RFC Validations.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateSerialNumberValidator implements CommonValidator<CACertificateValidationInfo> {
    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateSerialNumber(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateSerialNumber(final String caName, final X509Certificate x509Certificate) throws MissingMandatoryFieldException {

        final BigInteger serialNumber = x509Certificate.getSerialNumber();
        logger.debug("Validating X509Certificate SerialNumber for CA {} ", caName, "{} ", serialNumber);

        if (serialNumber.toByteArray().length > 20 || serialNumber.signum() == -1) {
            logger.error(ErrorMessages.SERIAL_NUMBER_VALIDATION_FAILED + " for CA {} ", caName, "and Serial Number is {} ", serialNumber);
            throw new MissingMandatoryFieldException(ErrorMessages.SERIAL_NUMBER_VALIDATION_FAILED);
        }
    }
}
