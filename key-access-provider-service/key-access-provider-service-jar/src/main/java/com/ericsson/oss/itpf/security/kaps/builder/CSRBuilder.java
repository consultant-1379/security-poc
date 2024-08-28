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

import java.security.PublicKey;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException;
import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.exception.SignatureException;
import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.common.utils.SignerUtility;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;

/**
 * This class creates {@link PKCS10CertificationRequest} with all the values like subject, public key and attributes.
 */
public class CSRBuilder {

    private static final Logger LOGGER = LoggerFactory.getLogger(CSRBuilder.class);

    @Inject
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Inject
    private SignerUtility signerUtility;

    /**
     * Generates Certificate Signing Request with extensions.
     * 
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param signatureAlgorithm
     *            signature algorithm using which the CSR needs to be generated
     * @param subject
     *            {@link X500Name} for which CSR should be generated
     * @param attributes
     *            extensions need to be generated in CSR.
     * @throws CSRGenerationException
     *             Thrown in case of any failures generating the CSR.
     * @throws KeyAccessProviderServiceException
     *             is thrown when there are any DB Errors.
     * @throws KeyIdentifierNotFoundException
     *             is thrown if public key is not fetched from KeyIdentifier provided
     */
    public PKCS10CertificationRequest buildPKCS10CertificationRequest(final KeyIdentifier keyIdentifier, final String signatureAlgorithm,
            final X500Name subject, final List<CertificateExtensionHolder> attributes) throws CSRGenerationException, KeyIdentifierNotFoundException,
            KeyAccessProviderServiceException {

        final PublicKey publicKey = keyPairPersistenceHandler.getPublicKey(keyIdentifier);

        final PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, publicKey);

        if (attributes != null) {
            final ExtensionsGenerator extensionsGenerator = generateExtensions(attributes);
            pkcs10CertificationRequestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensionsGenerator.generate());
        }

        try {
            final ContentSigner contentSigner = signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm);
            return pkcs10CertificationRequestBuilder.build(contentSigner);
        } catch (final SignatureException signatureException) {
            LOGGER.error(ErrorMessages.CSR_SIGNATURE_GENERATION_FAILED, signatureAlgorithm);
            throw new CSRGenerationException(ErrorMessages.CSR_SIGNATURE_GENERATION_FAILED, signatureException);
        }
    }

    private ExtensionsGenerator generateExtensions(final List<CertificateExtensionHolder> extensionsHolder) {
        final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();

        for (final CertificateExtensionHolder extensionHolder : extensionsHolder) {
            final ASN1ObjectIdentifier extensionOID = new ASN1ObjectIdentifier(extensionHolder.getExtnId());
            extensionsGenerator.addExtension(extensionOID, extensionHolder.isCritical(), extensionHolder.getValue());
        }

        return extensionsGenerator;
    }
}
