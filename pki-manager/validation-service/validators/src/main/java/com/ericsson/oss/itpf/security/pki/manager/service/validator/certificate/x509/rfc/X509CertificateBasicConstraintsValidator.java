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

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.utils.X509CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate BasicConstraints field of X509Certificate
 * 
 * @author tcsramc
 *
 */
public class X509CertificateBasicConstraintsValidator implements CommonValidator<CACertificateValidationInfo> {
    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {

        validateCertificateBasicConstraints(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateBasicConstraints(final String caName, final X509Certificate x509Certificate) throws InvalidBasicConstraintsExtension {
        final BasicConstraints basicConstraints = X509CertificateUtility.getBasicConstraints(x509Certificate);
        logger.debug("Validating X509Certificate BasicConstraints for CA  {} ", caName, " and Basic constraints value is {} ", basicConstraints);

        if (!basicConstraints.isCA()) {
            logger.error(ErrorMessages.BASIC_CONSTRAINTS_VALIDATION_FAILED + " for CA : {}" , caName);
            throw new InvalidBasicConstraintsExtension(ErrorMessages.BASIC_CONSTRAINTS_VALIDATION_FAILED);
        }
        final BigInteger pathLength = basicConstraints.getPathLenConstraint();
        if (pathLength != null) {
            if (pathLength.intValue() < 0) {
                logger.error(ErrorMessages.BASIC_CONSTRAINTS_PATH_VALIDATION_FAILED + " for CA : {}" , caName);
                throw new InvalidBasicConstraintsExtension(ErrorMessages.BASIC_CONSTRAINTS_PATH_VALIDATION_FAILED);
            }
        }
    }
}
