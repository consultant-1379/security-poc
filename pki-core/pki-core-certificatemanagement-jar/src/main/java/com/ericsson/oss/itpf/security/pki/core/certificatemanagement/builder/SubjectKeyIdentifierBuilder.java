/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.inject.Inject;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidSubjectKeyIdentifierException;

/**
 * This class builds {@link org.bouncycastle.asn1.x509.SubjectKeyIdentifier} extension for the certificate.
 * 
 */
public class SubjectKeyIdentifierBuilder {

    @Inject
    Logger logger;

    /**
     * Builds {@link SubjectKeyIdentifier} from certificate extension passed.
     * 
     * @param certificateExtension
     *            CertificateExtension that to be built as {@link SubjectKeyIdentifier}
     * @param publicKey
     *            public key passed to generate key identifier out of it.
     * @return Extension object that has SubjectKeyIdentifier.
     * @throws InvalidSubjectKeyIdentifierException
     *             Thrown in case if any failures occur in building extension.
     */
    public Extension buildSubjectKeyIdentifier(final CertificateExtension certificateExtension, final PublicKey publicKey) throws InvalidSubjectKeyIdentifierException {
        Extension extension = null;
        final SubjectKeyIdentifier subjectKeyIdentifier = (SubjectKeyIdentifier) certificateExtension;
        try {
            final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();

            logger.debug("Adding SubjectKeyIdentifier extension to the certificate extensions {} ", subjectKeyIdentifier);

            org.bouncycastle.asn1.x509.SubjectKeyIdentifier subjectKeyIdentifierExtension = null;
            if (subjectKeyIdentifier.getKeyIdentifier().getAlgorithm().getName().equals(Constants.KEYIDENTIFIER_TYPE1)) {
                subjectKeyIdentifierExtension = extUtils.createSubjectKeyIdentifier(publicKey);
            } else if (subjectKeyIdentifier.getKeyIdentifier().getAlgorithm().getName() == Constants.KEYIDENTIFIER_TYPE2) {
                subjectKeyIdentifierExtension = extUtils.createTruncatedSubjectKeyIdentifier(publicKey);
            }

            extension = new Extension(Extension.subjectKeyIdentifier, subjectKeyIdentifier.isCritical(), new DEROctetString(subjectKeyIdentifierExtension));
            return extension;

        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID, noSuchAlgorithmException);
            throw new InvalidSubjectKeyIdentifierException(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID);
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidSubjectKeyIdentifierException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }
}
