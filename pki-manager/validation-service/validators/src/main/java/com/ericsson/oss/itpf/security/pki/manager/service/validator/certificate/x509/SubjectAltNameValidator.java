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

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class Validates Subject Alternate Name of imported Certificate with the CSR.
 *
 * @author tcsnavg
 *
 */

public class SubjectAltNameValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Inject
    CSRExtensionUtils csrExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo caCertificateValidationInfo) throws ValidationException {

        validateSubjectAltName(caCertificateValidationInfo.getCaName(), caCertificateValidationInfo.getCertificate());

    }

    private void validateSubjectAltName(final String caName, final X509Certificate x509Certificate) throws InvalidSubjectAltNameExtension, MissingMandatoryFieldException {

        logger.debug("Validating SubjectAltName of imported X509Certificate with CSR for CA{}", caName);
        try {

            final SubjectAltName subjectAltName = (SubjectAltName) csrExtensionUtils.getCSRExtension(caName, CertificateExtensionType.SUBJECT_ALT_NAME);
            if (subjectAltName != null) {
                final List<SubjectAltNameField> csrSANFields = subjectAltName.getSubjectAltNameFields();

                final SubjectAltName certificateSubjectAltName = CertificateUtility.getSANFromCertificate(x509Certificate);
                final List<SubjectAltNameField> certificateSANFields = certificateSubjectAltName.getSubjectAltNameFields();

                for (final SubjectAltNameField csrSANField : csrSANFields) {
                    compareCSRandCertificateSANFields(csrSANField, certificateSANFields);
                }
            }
        } catch (final CertificateParsingException certificateParsingException) {
            logger.error(ErrorMessages.CERTIFICATE_PARSING_FAILED, " for CA {} ", caName, certificateParsingException.getMessage());
            throw new InvalidSubjectAltNameExtension(ErrorMessages.CERTIFICATE_PARSING_FAILED, certificateParsingException);

        } catch (final CertificateServiceException certificateServiceException) {
            logger.error(ErrorMessages.CSR_NOT_FOUND, " for CA {} ", caName, certificateServiceException.getMessage());
            throw new InvalidSubjectAltNameExtension(ErrorMessages.CSR_NOT_FOUND, certificateServiceException);
        }
    }

    private void compareCSRandCertificateSANFields(final SubjectAltNameField cSRSANField, final List<SubjectAltNameField> certificateSANFields) throws MissingMandatoryFieldException {
        boolean isSANPresent = false;
        for (final SubjectAltNameField certificateSANField : certificateSANFields) {
            if (certificateSANField.getType() != null && certificateSANField.getValue() != null) {
                if (certificateSANField.equals(cSRSANField)) {
                    isSANPresent = true;
                }
            }
        }
        if (!isSANPresent) {
            logger.error(ErrorMessages.SUBJECT_ALT_NAME_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_SUBJECT_ALT_NAME);
            throw new MissingMandatoryFieldException(ErrorMessages.SUBJECT_ALT_NAME_OF_CERTIFICATE_DOES_NOT_MATCH_WITH_CSR_SUBJECT_ALT_NAME);

        }
    }
}
