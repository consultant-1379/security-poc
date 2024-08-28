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

import java.security.PublicKey;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;

/**
 * Class that builds certificate extension data from {@link CertificateGenerationInfo} and CSR
 */
public class ExtensionBuilder {

    // TODO : This class needs to be modified. User story ref : TORF-54827

    @Inject
    AuthorityInformationAccessBuilder authorityInformationAccessBuilder;

    @Inject
    AuthorityKeyIdentifierBuilder authorityKeyIdentifierBuilder;

    @Inject
    BasicConstraintsBuilder basicConstraintsBuilder;

    @Inject
    CRLDistributionPointsBuilder cRLDistributionPointsBuilder;

    @Inject
    ExtendedKeyUsageBuilder extendedKeyUsageBuilder;

    @Inject
    KeyUsageBuilder keyUsageBuilder;

    @Inject
    SubjectAltNameBuilder subjectAltNameBuilder;

    @Inject
    SubjectKeyIdentifierBuilder subjectKeyIdentifierBuilder;

    @Inject
    Logger logger;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Build certificate extensions from the {@link CertificateGenerationInfo} object.
     * 
     * @param certificateGenerationInfo
     *            certificateGenerationInfo passed to build the certificate extensions
     * @param publicKey
     *            public key passed to build the certificate extensions
     * @return list of extensions which needs to be used to generate a certificate.
     * @throws InvalidCertificateExtensionsException
     *             Thrown in case if any failure occur while building certificate extensions.
     */
    public List<Extension> buildCertificateExtensions(final CertificateGenerationInfo certificateGenerationInfo, final PublicKey publicKey) throws InvalidCertificateExtensionsException {

        final List<Extension> extensions = new ArrayList<>();

        final String entityName = certificateGenerationInfo.getCAEntityInfo() == null ? certificateGenerationInfo.getEntityInfo().getName() : certificateGenerationInfo.getCAEntityInfo().getName();

        logger.debug("Certificate extension preparation started for {}", entityName);

        final List<CertificateExtension> certificateExtensions = certificateGenerationInfo.getCertificateExtensions().getCertificateExtensions();

        for (final CertificateExtension certificateExtension : certificateExtensions) {
            addExtension(certificateGenerationInfo, publicKey, certificateExtension, extensions);
        }

        logger.debug("Done with preparation of certificate extensions {}", certificateGenerationInfo);

        return extensions;
    }

    private void addExtension(final CertificateGenerationInfo certificateGenerationInfo, final PublicKey publicKey, final CertificateExtension certExtension, final List<Extension> extensions)
            throws InvalidCertificateExtensionsException {

        try {
            if (certExtension instanceof SubjectKeyIdentifier) {
                extensions.add(subjectKeyIdentifierBuilder.buildSubjectKeyIdentifier(certExtension, publicKey));
            } else if (certExtension instanceof AuthorityKeyIdentifier) {
                extensions.add(authorityKeyIdentifierBuilder.buildAuthorityIdentifier(certificateGenerationInfo, certExtension, publicKey, null));
            } else if (certExtension instanceof AuthorityInformationAccess) {
                extensions.add(authorityInformationAccessBuilder.buildAuthorityInformationAccess(certExtension));
            } else if (certExtension instanceof BasicConstraints) {
                extensions.add(basicConstraintsBuilder.buildBasicConstraints(certExtension));
            } else if (certExtension instanceof KeyUsage) {
                extensions.add(keyUsageBuilder.buildKeyUsage(certExtension));
            } else if (certExtension instanceof ExtendedKeyUsage) {
                extensions.add(extendedKeyUsageBuilder.buildExtendedKeyUsage(certExtension));
            } else if (certExtension instanceof CRLDistributionPoints) {
                extensions.add(cRLDistributionPointsBuilder.buildCRLDistributionPoints(certExtension));
            } else if (certExtension instanceof SubjectAltName) {
                extensions.add(subjectAltNameBuilder.buildSubjectAltName(certExtension, certificateGenerationInfo));
            }
        } catch (InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            logger.error(ErrorMessages.INVALID_CERTIFICATE_EXTENSION, invalidCertificateExtensionsException);
            throw invalidCertificateExtensionsException;
        }
    }

    /**
     * @param certificateExtensions
     * @return list of CertificateExtensionHolder objects
     */
    public List<CertificateExtensionHolder> getCertificateExtensionHolders(final List<Extension> certificateExtensions) {
        final List<CertificateExtensionHolder> certificateExtensionHolders = new ArrayList<>();
        for (final Extension extension : certificateExtensions) {
            if (extension != null) {
                final CertificateExtensionHolder certificateExtensionHolder = new CertificateExtensionHolder(extension.getExtnId().getId(), extension.isCritical(), extension.getExtnValue()
                        .getOctets());
                certificateExtensionHolders.add(certificateExtensionHolder);
                logger.debug("Adding certificate extension to the holder {}", extension.getExtnId());
            }
        }
        return certificateExtensionHolders;
    }
}
