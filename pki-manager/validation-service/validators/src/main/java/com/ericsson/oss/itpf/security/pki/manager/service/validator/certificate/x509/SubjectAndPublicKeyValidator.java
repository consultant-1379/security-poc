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
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.CertificateRequestUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class Validates Imported Certificate with the CSR.
 * 
 * @author tcsramc
 *
 */
public class SubjectAndPublicKeyValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateSubjectAndPublicKey(cACertificateValidationInfo);
    }

    private void validateSubjectAndPublicKey(final CACertificateValidationInfo cACertificateValidationInfo) throws CertificateFieldException, InvalidOperationException, InvalidSubjectException {
        final String caName = cACertificateValidationInfo.getCaName();
        try {
            final CertificateGenerationInfoData certificateGenerationInfoData = caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName);
            final JcaPKCS10CertificationRequest certificationRequest = CertificateRequestUtility.getJCAPKCS10CertificationRequest(certificateGenerationInfoData.getCertificateRequestData().getCsr());

            validateCSROfCertGenInfo(certificateGenerationInfoData, caName);
            validateSubject(cACertificateValidationInfo.getCertificate(), certificationRequest, caName);
            validatePublicKey(cACertificateValidationInfo.getCertificate(), cACertificateValidationInfo.getCaName());
        } catch (IOException iOException) {
            logger.error(ErrorMessages.IO_EXCEPTION, "for CA {} ", caName, "{} ", iOException.getMessage());
            throw new InvalidOperationException(ErrorMessages.IO_EXCEPTION, iOException);

        }

    }

    private void validateCSROfCertGenInfo(final CertificateGenerationInfoData certificateGenerationInfoData, final String caName) throws InvalidOperationException {
        if (certificateGenerationInfoData == null || certificateGenerationInfoData.getCertificateRequestData() == null) {
            logger.error(ErrorMessages.CSR_NOT_FOUND, "for CA {} ", caName);
            throw new InvalidOperationException(ErrorMessages.CSR_NOT_FOUND);
        }
    }

    private void validateSubject(final X509Certificate x509Certificate, final JcaPKCS10CertificationRequest certificationRequest, final String caName) throws InvalidSubjectException {
        logger.debug("Validating X509Certificate subject with CSR {} ", caName);
        try {
            final X500Name subjectDN = new JcaX509CertificateHolder(x509Certificate).getSubject();
            validateSubjectDNOfCertWithCSR(subjectDN, certificationRequest.getSubject(), caName);
        } catch (CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, "for CA {} ", caName, certificateEncodingException.getMessage());
            throw new InvalidSubjectException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
        }
    }

    private void validateSubjectDNOfCertWithCSR(final X500Name subjectDNOfCert, final X500Name subjectDNOfCsr, final String caName) throws InvalidSubjectException {
        if (!subjectDNOfCert.equals(subjectDNOfCsr)) {
            logger.error(ErrorMessages.SUBJECT_DN_OF_CSR_DOES_NOT_MATCH_WITH_CERTIFICATE_SUBJECT_DN, "for CA {} ", caName);
            throw new InvalidSubjectException(ErrorMessages.SUBJECT_DN_OF_CSR_DOES_NOT_MATCH_WITH_CERTIFICATE_SUBJECT_DN);
        }
    }

    private void validatePublicKey(final X509Certificate certificate, final String caName) throws CertificateFieldException {
        try {
            final CertificateGenerationInfoData certificateGenerationInfoData = caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName);
            final byte[] csr = certificateGenerationInfoData.getCertificateRequestData().getCsr();

            final JcaPKCS10CertificationRequest certificationRequest = CertificateRequestUtility.getJCAPKCS10CertificationRequest(csr);

            validatePublicKeyOfCertWithCSR(certificate.getPublicKey(), certificationRequest.getPublicKey(), caName);
        } catch (InvalidKeyException | NoSuchAlgorithmException | IOException exception) {
            logger.error(ErrorMessages.INVALID_PUBLIC_KEY, "for cA {} ", caName, exception.getMessage());
            throw new CertificateFieldException(ErrorMessages.INVALID_PUBLIC_KEY, exception);
        }
    }

    private void validatePublicKeyOfCertWithCSR(final PublicKey publicKeyInCert, final PublicKey publicKeyInCsr, final String caName) throws CertificateFieldException {
        if (!publicKeyInCert.equals(publicKeyInCsr)) {
            logger.error(ErrorMessages.PUBLIC_KEY_OF_CSR_DOES_NOT_MATCH_WITH_CERTIFICATE_PUBLIC_KEY, " for CA {} ", caName);
            throw new CertificateFieldException(ErrorMessages.PUBLIC_KEY_OF_CSR_DOES_NOT_MATCH_WITH_CERTIFICATE_PUBLIC_KEY);
        }
    }
}
