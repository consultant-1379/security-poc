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

package com.ericsson.oss.itpf.security.kaps.builder;

import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.utils.TextToBinaryUtility;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v3CertificateBuilderHolder;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;

/**
 * Class for build X509v3CertificateBuilder object with {@link X509v3CertificateBuilderHolder}
 *
 * @author tcsrcho
 */
public class CertificateBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateBuilder.class);

    /**
     * Converts {@link X509v3CertificateBuilderHolder} to {@link X509v3CertificateBuilder}
     *
     * @param x509v3CertBuilderHolder
     *            The X509v3CertificateBuilderHolder
     * @param issuerDN
     *            The X500Principal Object
     * @return {@link X509v3CertificateBuilder}
     * @throws InvalidCertificateExtensionsException
     *             is thrown when certificate extensions are not valid.
     */
    public X509v3CertificateBuilder buildX509v3CertificateBuilder(final X509v3CertificateBuilderHolder x509v3CertBuilderHolder,
            final X500Principal issuerDN) throws InvalidCertificateExtensionsException {
        X509v3CertificateBuilder certificateBuilder = null;
        final SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo
                .getInstance(x509v3CertBuilderHolder.getSubjectPublicKey().getEncoded());
        X500Name x500Name = null;
        if (issuerDN != null) {
            x500Name = X500Name.getInstance(issuerDN.getEncoded());
        } else {
            x500Name = new X500Name(x509v3CertBuilderHolder.getIssuerDN());
        }
        certificateBuilder = new X509v3CertificateBuilder(x500Name, x509v3CertBuilderHolder.getSerialNumber(), x509v3CertBuilderHolder.getNotBefore(),
                x509v3CertBuilderHolder.getNotAfter(), new X500Name(x509v3CertBuilderHolder.getSubjectDN()), subjectPublicKeyInfo);
        // TODO : TORF-97038 - Enable Subject Unique Identifiers in Certificate
        final String subjectUniqueIdentifierValue = x509v3CertBuilderHolder.getSubjectUniqueIdentifierValue();
        if (subjectUniqueIdentifierValue != null ) {
            certificateBuilder.setSubjectUniqueID(TextToBinaryUtility.getTextAsBinary(subjectUniqueIdentifierValue));
            LOGGER.debug("Added subject unique identifier to X509Certificate {} ", subjectUniqueIdentifierValue);
        }

        if (x509v3CertBuilderHolder.isIssuerUniqueIdentifier()) {
            // This will be changed when CertificateGenerationInfo model is changed. Unique identifiers will be changed to strings and converted to
            // binary to form in certificate.
            certificateBuilder.setIssuerUniqueID(new boolean[] { x509v3CertBuilderHolder.isIssuerUniqueIdentifier() });
            LOGGER.debug("Added issuer unique identifier to X509Certificate {} ", x509v3CertBuilderHolder.isSubjectUniqueIdentifier());
        }

        final List<CertificateExtensionHolder> certificateExtensionHolders = x509v3CertBuilderHolder.getCertificateExtensionHolders();
        if (!ValidationUtils.isNullOrEmpty(certificateExtensionHolders)) {
            try {
                for (final CertificateExtensionHolder certificateExtensionHolder : certificateExtensionHolders) {
                    if (certificateExtensionHolder != null) {
                        certificateBuilder.addExtension(new ASN1ObjectIdentifier(certificateExtensionHolder.getExtnId()),
                                certificateExtensionHolder.isCritical(), certificateExtensionHolder.getValue());
                    }
                }
            } catch (final CertIOException certIOException) {
                LOGGER.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, certIOException);
                throw new InvalidCertificateExtensionsException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
            }
        }

        return certificateBuilder;
    }
}
