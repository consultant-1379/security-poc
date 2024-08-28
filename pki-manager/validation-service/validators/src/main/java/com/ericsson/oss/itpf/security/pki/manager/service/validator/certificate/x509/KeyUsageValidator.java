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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class Validates KeyUsage of imported Certificate with the CSR.
 *
 * @author tcsnavg
 *
 */
public class KeyUsageValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Inject
    CSRExtensionUtils csrExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo caCertificateValidationInfo) throws ValidationException {

        validateKeyUsage(caCertificateValidationInfo.getCaName(), caCertificateValidationInfo.getCertificate());
    }

    private void validateKeyUsage(final String caName, final X509Certificate x509Certificate) throws CertificateServiceException, MissingMandatoryFieldException {

        logger.debug("Validating KeyUsage of imported X509Certificate with CSR for CA{}", caName);

        final List<Integer> csrKeyUsageIds = getCSRKeyUsageIds(caName);

        final List<Integer> certificateKeyUsageIds = getCertificateKeyUsageIds(x509Certificate);

        final boolean isFieldValueSame = certificateExtensionUtils.compareCSRandCertificateFields(csrKeyUsageIds, certificateKeyUsageIds);
        if (!isFieldValueSame) {
            logger.error(ErrorMessages.KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_KEY_USAGE);
            throw new MissingMandatoryFieldException(ErrorMessages.KEY_USAGE_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_KEY_USAGE);
        }
    }

    private List<Integer> getCSRKeyUsageIds(final String caName) {
        final KeyUsage keyUsage = (KeyUsage) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.KEY_USAGE);
        final List<KeyUsageType> csrKeyUsageTypes = keyUsage.getSupportedKeyUsageTypes();
        final List<Integer> csrKeyUsageIds = new ArrayList<Integer>();
        for (final KeyUsageType keyUsageType : csrKeyUsageTypes) {
            csrKeyUsageIds.add(keyUsageType.getId());
        }
        return csrKeyUsageIds;
    }

    private List<Integer> getCertificateKeyUsageIds(final X509Certificate x509Certificate) {
        final boolean[] certificateKeyUsages = x509Certificate.getKeyUsage();
        final List<Integer> certificateKeyUsageIds = new ArrayList<Integer>();
        for (int keyUsageId = 0; keyUsageId < certificateKeyUsages.length; keyUsageId++) {
            if (certificateKeyUsages[keyUsageId]) {
                certificateKeyUsageIds.add(keyUsageId);
            }
        }
        return certificateKeyUsageIds;
    }
}
