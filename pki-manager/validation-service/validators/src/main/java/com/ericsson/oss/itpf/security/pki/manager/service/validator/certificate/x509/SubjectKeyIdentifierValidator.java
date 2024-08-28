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

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.Arrays;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class Validates SubjectKeyIdentifier of imported Certificate with the CSR.
 *
 * @author tcsnavg
 *
 */
public class SubjectKeyIdentifierValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Inject
    CSRExtensionUtils csrExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo caCertificateValidationInfo) throws ValidationException {

        validateSubjectKeyIdentifier(caCertificateValidationInfo.getCaName(), caCertificateValidationInfo.getCertificate());

    }

    private void validateSubjectKeyIdentifier(final String caName, final X509Certificate x509Certificate) throws CertificateServiceException, InvalidSubjectKeyIdentifierExtension,
            MissingMandatoryFieldException {

        logger.debug("Validating SubjectKeyIdentifier of imported X509Certificate with CSR for CA{}", caName);
        final byte[] certificateSubjectKeyIdentifierExtensionValue = certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.subjectKeyIdentifier.getId());
        final byte[] csrSubjectKeyIdentifierExtensionValue = csrExtensionUtils.getCSRAttributeExtensionValue(caName, Extension.subjectKeyIdentifier);

        if (!Arrays.areEqual(certificateSubjectKeyIdentifierExtensionValue, csrSubjectKeyIdentifierExtensionValue)) {
            logger.error(ErrorMessages.SUBJECT_KEY_IDENTIFIER_NOT_FOUND_IN_CERTIFICATE + " for CA {} ", caName);
            throw new InvalidSubjectKeyIdentifierExtension(ErrorMessages.SUBJECT_KEY_IDENTIFIER_NOT_FOUND_IN_CERTIFICATE);
        }

    }
}
