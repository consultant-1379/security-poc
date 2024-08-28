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
import java.util.Set;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.utils.X509CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class validates KeyUsage Field of X509Certificate as per RFC Validations.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateKeyUsageValidator implements CommonValidator<CACertificateValidationInfo> {
    @Inject
    Logger logger;

    public static final int KEYY_CERT_SIGN_INDEX = 5;
    public static final int CRL_SIGN_INDEX = 6;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateKeyUsage(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateKeyUsage(final String caName, final X509Certificate x509Certificate) throws InvalidKeyUsageExtension, MissingMandatoryFieldException {

        final boolean[] keyUsage = x509Certificate.getKeyUsage();
        logger.debug("Validating X509Certificate KeyUsage {} for CA{}  ", caName, "{} ", keyUsage);
        validateKeyUsageNull(keyUsage, caName);
        validateKeyUsageCritical(x509Certificate, caName);
        validateKeyUsageTypes(keyUsage, caName);
        validateKeyCertSign(x509Certificate, caName);

    }

    private void validateKeyUsageNull(final boolean[] keyUsage, final String caName) throws MissingMandatoryFieldException {
        if (keyUsage == null || keyUsage.length == 0) {
            logger.error(ErrorMessages.KEY_USAGE_MANDATORY_FOR_CA, " for CA {} ", caName);
            throw new MissingMandatoryFieldException(ErrorMessages.KEY_USAGE_MANDATORY_FOR_CA);
        }
    }

    private void validateKeyUsageCritical(final X509Certificate x509Certificate, final String caName) throws InvalidKeyUsageExtension {
        final Set<String> criticalExtensionOIDs = x509Certificate.getCriticalExtensionOIDs();

        if (!criticalExtensionOIDs.contains(Extension.keyUsage.getId())) {
            logger.error("{} for CA {}", ErrorMessages.KEY_USAGE_EXTENSION_VALIDATION_FAILED, caName);
            throw new InvalidKeyUsageExtension(ErrorMessages.KEY_USAGE_EXTENSION_VALIDATION_FAILED);
        }
    }

    private void validateKeyUsageTypes(final boolean[] keyUsages, final String caName) throws InvalidKeyUsageExtension {
        if (!keyUsages[KEYY_CERT_SIGN_INDEX]) {
            logger.error(ErrorMessages.KEY_USAGE_TYPE_VALIDATION_FAILED, " for CA {} ", caName);
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_KEY_CERT_SIGN);
        }
        if (!keyUsages[CRL_SIGN_INDEX]) {
            logger.error(ErrorMessages.KEY_USAGE_TYPE_VALIDATION_FAILED, " for CA {} ", caName);
            throw new InvalidKeyUsageExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.REQUIRED_CRL_SIGN);
        }

    }

    private void validateKeyCertSign(final X509Certificate x509Certificate, final String caName) throws InvalidKeyUsageExtension {
        final boolean isCA = isCAFromBasicConstraints(x509Certificate, caName);
        if (!isCA) {
            logger.error("Key CertSign is asserted ,But{} for CA {}", ErrorMessages.BASIC_CONSTRAINTS_VALIDATION_FAILED, caName);
            throw new InvalidKeyUsageExtension("Key CertSign is asserted ,But{}" + ErrorMessages.BASIC_CONSTRAINTS_VALIDATION_FAILED);
        }

    }

    private boolean isCAFromBasicConstraints(final X509Certificate x509Certificate, final String caName) throws InvalidKeyUsageExtension {
        BasicConstraints basicConstraints = null;
        try {
            basicConstraints = X509CertificateUtility.getBasicConstraints(x509Certificate);
        } catch (final InvalidBasicConstraintsExtension invalidBasicConstraintsExtension) {
            logger.debug("Exception occured while reading input Stream for CA {} ",caName, invalidBasicConstraintsExtension);
            logger.error(ErrorMessages.BASIC_CONSTRAINTS_NULL + "or" + ErrorMessages.IO_EXCEPTION + "for CA {}" + caName);
            throw new InvalidKeyUsageExtension(ErrorMessages.BASIC_CONSTRAINTS_NULL + "or" + ErrorMessages.IO_EXCEPTION);

        }
        return basicConstraints.isCA();
    }

}
