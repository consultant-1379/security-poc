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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509;

import java.math.BigInteger;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.utils.X509CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class Validates BasicConstraints of imported Certificate with the CSR.
 *
 * @author tcsnavg
 *
 */
public class BasicConstraintsValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo caCertificateValidationInfo) throws ValidationException {

        validateBasicConstraints(caCertificateValidationInfo.getCaName(), caCertificateValidationInfo.getCertificate());

    }

    private void validateBasicConstraints(final String caName, final X509Certificate x509Certificate) throws InvalidBasicConstraintsExtension {

        logger.debug("Validating BasicConstraints of imported X509Certificate with CSR for CA{}", caName);

        final BasicConstraints certificateBasicConstraints = X509CertificateUtility.getBasicConstraints(x509Certificate);
        final BigInteger pathLength = certificateBasicConstraints.getPathLenConstraint();

        validateIsCAField(certificateBasicConstraints, caName);
        validatePathLengthConstraint(pathLength, caName);

    }

    private void validateIsCAField(final BasicConstraints certificateBasicConstraints, final String caName) throws InvalidBasicConstraintsExtension {
        if (!certificateBasicConstraints.isCA()) {
            logger.error(ErrorMessages.BASIC_CONSTRAINTS_VALIDATION_FAILED + "{} for CA : " , caName);
            throw new InvalidBasicConstraintsExtension(ErrorMessages.BASIC_CONSTRAINTS_VALIDATION_FAILED);
        }
    }

    private void validatePathLengthConstraint(final BigInteger pathLength, final String caName) throws InvalidBasicConstraintsExtension {
        if ((pathLength != null) && pathLength.intValue() < 0) {
            logger.error(ErrorMessages.BASIC_CONSTRAINTS_PATH_VALIDATION_FAILED + "{} for CA : " , caName);
            throw new InvalidBasicConstraintsExtension(ErrorMessages.BASIC_CONSTRAINTS_PATH_VALIDATION_FAILED);
        }
    }
}
