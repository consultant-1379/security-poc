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

import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.operator.DigestCalculator;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This Class Validates SubjectKeyIdentifier of X509Certificate as per RFCValidations.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateSubjectKeyIdentifierValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    public static final String ALGORITHM = "SHA-1";
    public static final String BITS_TO_APPEND = "0100";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateSubjectKeyIdentifier(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateSubjectKeyIdentifier(final String caName, final X509Certificate x509Certificate) throws InvalidSubjectKeyIdentifierExtension, MissingMandatoryFieldException {
        logger.debug("Validate x509 certificate SubjectKeyIdenifier for CA {} ", caName);
        try {
            final JcaX509ExtensionUtils jcaX509ExtensionUtils = new JcaX509ExtensionUtils();
            final SubjectKeyIdentifier keyIdentifierFromPubKey = jcaX509ExtensionUtils.createSubjectKeyIdentifier(x509Certificate.getPublicKey());

            final DigestCalculator calculator = new SHA1DigestCalculator(MessageDigest.getInstance(ALGORITHM));
            final X509ExtensionUtils x509CertificateUtils = new X509ExtensionUtils(calculator);
            final SubjectKeyIdentifier keyIdentifierwith60bitsFromPubKey = x509CertificateUtils.createTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(x509Certificate.getPublicKey()
                    .getEncoded()));

            final SubjectKeyIdentifier subjectKeyIdentifierFromCertificate = getSubjectKeyIdentifierFromCertificate(x509Certificate);

            if (!keyIdentifierFromPubKey.equals(subjectKeyIdentifierFromCertificate) && !keyIdentifierwith60bitsFromPubKey.equals(subjectKeyIdentifierFromCertificate)) {
                logger.error(ErrorMessages.SUBJECT_KEY_IDENTIFIER_VALIDATION_FAILED + " for CA {} ", caName);
                throw new InvalidSubjectKeyIdentifierExtension(ErrorMessages.SUBJECT_KEY_IDENTIFIER_VALIDATION_FAILED);
            }
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, " for CA {} ", caName, noSuchAlgorithmException.getMessage());
            throw new InvalidSubjectKeyIdentifierExtension(ErrorMessages.ALGORITHM_IS_NOT_FOUND, noSuchAlgorithmException);
        }

    }

    private SubjectKeyIdentifier getSubjectKeyIdentifierFromCertificate(final X509Certificate x509Certificate) throws MissingMandatoryFieldException {
        final byte[] extensionValue = certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.subjectKeyIdentifier.getId());
        final ASN1OctetString asn1OctectString = ASN1OctetString.getInstance(extensionValue);
        return SubjectKeyIdentifier.getInstance(asn1OctectString.getOctets());
    }

    private static class SHA1DigestCalculator implements DigestCalculator {
        final private ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        final private MessageDigest digest;

        public SHA1DigestCalculator(final MessageDigest digest) {
            this.digest = digest;
        }

        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1);
        }

        public OutputStream getOutputStream() {
            return bOut;
        }

        public byte[] getDigest() {
            final byte[] bytes = digest.digest(bOut.toByteArray());

            bOut.reset();

            return bytes;
        }
    }

}
