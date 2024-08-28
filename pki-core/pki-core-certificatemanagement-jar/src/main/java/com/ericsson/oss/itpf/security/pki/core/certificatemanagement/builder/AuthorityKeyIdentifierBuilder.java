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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidAuthorityKeyIdentifierException;

/**
 * This class builds {@link org.bouncycastle.asn1.x509.AuthorityKeyIdentifier} extension for the certificate.
 */
public class AuthorityKeyIdentifierBuilder {

    @Inject
    CertificateGenerationInfoParser certGenInfoParser;

    @Inject
    CertificatePersistenceHelper persistenceHelper;

    @Inject
    Logger logger;

    /**
     * Builds {@link AuthorityKeyIdentifier} extension from CertificateExtension and {@link CertificateGenerationInfo} passed.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} passed to build AuthorityKeyIdentifier.
     * @param certificateExtension
     *            CertificateExtension that to be built as AuthorityKeyIdentifier.
     * @param publicKey
     *            public key passed to generate key identifier out of it.
     * @param serialNumber
     * @return Extension object that has AuthorityKeyIdentifier.
     * @throws InvalidAuthorityKeyIdentifierException
     *             Thrown in case if any failures occur in building extension.
     */
    public Extension buildAuthorityIdentifier(final CertificateGenerationInfo certificateGenerationInfo, final CertificateExtension certificateExtension, final PublicKey publicKey,
            final String serialNumber) throws InvalidAuthorityKeyIdentifierException {

        final AuthorityKeyIdentifier authorityKeyIdentifier = (AuthorityKeyIdentifier) certificateExtension;
        logger.debug("Adding AuthorityKeyIdentifier extension to certifcate extensions {} ", authorityKeyIdentifier);

        try {
            Extension extension = null;
            DEROctetString authorityKeyIdentifierExtension = null;
            if (certificateGenerationInfo.getIssuerCA() == null) {
                if (authorityKeyIdentifier.getType() == AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER) {
                    final org.bouncycastle.asn1.x509.SubjectPublicKeyInfo apki = new org.bouncycastle.asn1.x509.SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(
                            publicKey.getEncoded())).readObject());
                    authorityKeyIdentifierExtension = new DEROctetString(new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(apki));
                    extension = new Extension(Extension.authorityKeyIdentifier, authorityKeyIdentifier.isCritical(), authorityKeyIdentifierExtension);
                } else {
                    authorityKeyIdentifierExtension = getAuthorityKeyIdentifierByIssuerNameAndSerialNumber(certificateGenerationInfo, serialNumber);
                    extension = new Extension(Extension.authorityKeyIdentifier, authorityKeyIdentifier.isCritical(), authorityKeyIdentifierExtension);
                }
            } else {
                authorityKeyIdentifierExtension = getAuthorityKeyIdentifier(certificateGenerationInfo.getIssuerCA().getName(), serialNumber);
                extension = new Extension(Extension.authorityKeyIdentifier, authorityKeyIdentifier.isCritical(), authorityKeyIdentifierExtension);
            }
            return extension;
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidAuthorityKeyIdentifierException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }

    }

    private DEROctetString getAuthorityKeyIdentifier(final String cAName, final String serialNumber) throws InvalidAuthorityKeyIdentifierException {

        DEROctetString authorityKeyIdentifier = null;

        final CertificateAuthorityData issuerCA = persistenceHelper.getCA(cAName);
        try {
            final JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            final CertificateData certificate = getCertificate(issuerCA, serialNumber);
            final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificate.getCertificate());
            final X509Certificate x509Certificate = new JcaX509CertificateConverter().getCertificate(certificateHolder);

            authorityKeyIdentifier = new DEROctetString(extUtils.createAuthorityKeyIdentifier(x509Certificate.getPublicKey()));
            return authorityKeyIdentifier;
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            logger.error(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID, noSuchAlgorithmException);
            throw new InvalidAuthorityKeyIdentifierException(ErrorMessages.ALGORITHM_TO_BUILD_KEY_IDENTIFIER_IS_INVALID);
        } catch (CertificateException certificateException) {
            logger.error(ErrorMessages.CERTIFICATE_EXCEPTION, certificateException);
            throw new InvalidAuthorityKeyIdentifierException(ErrorMessages.CERTIFICATE_EXCEPTION);
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidAuthorityKeyIdentifierException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }

    private DEROctetString getAuthorityKeyIdentifierByIssuerNameAndSerialNumber(final CertificateGenerationInfo certificateGenerationInfo, final String serialNumber)
            throws InvalidAuthorityKeyIdentifierException {

        final org.bouncycastle.asn1.x509.GeneralName generalName = new org.bouncycastle.asn1.x509.GeneralName(new X500Name(
                certGenInfoParser.getIssuerDNFromCertGenerationInfo(certificateGenerationInfo)));
        final org.bouncycastle.asn1.x509.GeneralNames issuerName = new org.bouncycastle.asn1.x509.GeneralNames(generalName);
        final CertificateData issuerCertificate = getCertificate(persistenceHelper.getCA(certificateGenerationInfo.getIssuerCA().getName()), serialNumber);
        final BigInteger issuerSerialNumber = new BigInteger(issuerCertificate.getSerialNumber());
        try {
            return new DEROctetString(new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(issuerName, issuerSerialNumber));
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidAuthorityKeyIdentifierException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }

    private CertificateData getCertificate(final CertificateAuthorityData certificateAuthorityData, final String serialNumber) {

        CertificateData activeCertificateData = new CertificateData();
        final Set<CertificateData> certificates = certificateAuthorityData.getCertificateDatas();
        for (final CertificateData certData : certificates) {
            if (serialNumber == null) {
                if (certData.getStatus() == CertificateStatus.ACTIVE) {
                    activeCertificateData = certData;
                }
            } else if (certData.getSerialNumber().equals(serialNumber)) {
                activeCertificateData = certData;
            }
        }
        return activeCertificateData;
    }

}
