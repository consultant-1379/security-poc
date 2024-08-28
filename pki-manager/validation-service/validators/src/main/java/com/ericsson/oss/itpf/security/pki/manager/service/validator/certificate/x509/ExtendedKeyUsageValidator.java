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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class Validates ExtendedKeyUsage of imported Certificate with the CSR.
 *
 * @author tcsnavg
 *
 */
public class ExtendedKeyUsageValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Inject
    CSRExtensionUtils csrExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo caCertificateValidationInfo) throws ValidationException {

        validateExtendedKeyUsage(caCertificateValidationInfo.getCaName(), caCertificateValidationInfo.getCertificate());
    }

    private void validateExtendedKeyUsage(final String caName, final X509Certificate x509Certificate) throws CertificateServiceException, InvalidExtendedKeyUsageExtension,
            MissingMandatoryFieldException {

        logger.debug("Validating ExtendedKeyUsage of imported X509Certificate with CSR for CA{}", caName);

        final ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.EXTENDED_KEY_USAGE);
        if (extendedKeyUsage != null) {
            final List<String> csrExtendedKeyUsageOIDs = getCSRExtendedKeyUsageFields(extendedKeyUsage);
            final List<String> certificateExtendedKeyUsageOIDs = getCertificateExtendedKeyUsageFields(caName, x509Certificate);

            final boolean isFieldValueSame = certificateExtensionUtils.compareCSRandCertificateFields(csrExtendedKeyUsageOIDs, certificateExtendedKeyUsageOIDs);
            if (!isFieldValueSame) {
                logger.error(ErrorMessages.EXTENDED_KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_EXTENDED_KEY_USAGE);
                throw new MissingMandatoryFieldException(ErrorMessages.EXTENDED_KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_EXTENDED_KEY_USAGE);
            }
        }
    }

    private List<String> getCSRExtendedKeyUsageFields(final ExtendedKeyUsage extendedKeyUsage) {
        final List<KeyPurposeId> supportedKeyPurposeIds = extendedKeyUsage.getSupportedKeyPurposeIds();
        final List<String> csrOIDs = new ArrayList<String>();
        for (final KeyPurposeId keyPurposeId : supportedKeyPurposeIds) {
            csrOIDs.add(keyPurposeId.getOID());
        }
        return csrOIDs;
    }

    private List<String> getCertificateExtendedKeyUsageFields(final String caName, final X509Certificate x509Certificate) throws InvalidExtendedKeyUsageExtension {
        final List<String> certificateExtendedKeyUsageOIDs = new ArrayList<String>();
        try {
            final byte[] extensionValue = x509Certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
            if (extensionValue != null) {
                final org.bouncycastle.asn1.x509.KeyPurposeId[] keyPurposeIDs = certificateExtensionUtils.getKeyPurposeID(extensionValue);
                for (final org.bouncycastle.asn1.x509.KeyPurposeId id : keyPurposeIDs) {
                    certificateExtendedKeyUsageOIDs.add(id.getId());
                }
            }
        } catch (final IOException iOException) {
            logger.error(ErrorMessages.IO_EXCEPTION, "for CA {} ", caName, iOException.getMessage());
            throw new InvalidExtendedKeyUsageExtension(ErrorMessages.IO_EXCEPTION, iOException);
        }
        return certificateExtendedKeyUsageOIDs;
    }
}
