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

package com.ericsson.oss.itpf.security.kaps.impl.service;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.*;
import com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException;
import com.ericsson.oss.itpf.security.kaps.crl.exception.SignCRLException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.exception.NotSupportedException;
import com.ericsson.oss.itpf.security.kaps.impl.KeyAccessProviderManager;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509CRLHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v2CRLBuilderHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v3CertificateBuilderHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;

/**
 * Implementation for all the key related operations {@link KeyAccessProviderService}
 */
@Profiled
@Stateless
public class KeyAccessProviderServiceBean implements KeyAccessProviderService {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyAccessProviderServiceBean.class);
    private static final String KEY_ACCESS_PROVIDER_SERVICE = "KeyAccessProviderService";
    private static final String KEY_ACCESS_PROVIDER_MANAGER_BEAN = "KeyAccessProviderManagerBean";
    private static final String SUCCESS = "SUCCESS";

    @Inject
    KeyAccessProviderManager keyAccessProviderManager;

    @Inject
    private SystemRecorder systemRecorder;

    @Override
    public KeyIdentifier generateKeyPair(final String algorithm, final Integer modulus) throws KeyAccessProviderServiceException,
            KeyPairGenerationException {

        LOGGER.debug("Generate key pair with algorithm {} and key size {}", algorithm, modulus);

        final KeyIdentifier keyIdentifier = keyAccessProviderManager.generateKeyPair(algorithm, modulus);

        LOGGER.debug("Keypair Generated Sucessfully.");

        systemRecorder.recordSecurityEvent(KEY_ACCESS_PROVIDER_SERVICE, KEY_ACCESS_PROVIDER_MANAGER_BEAN, "KeyPair generated ",
                "KAPS.GENERATE_KEYPAIR", ErrorSeverity.INFORMATIONAL, SUCCESS);

        return keyIdentifier;
    }

    @Override
    public PublicKey getPublicKey(final KeyIdentifier keyIdentifier) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        LOGGER.debug("Getting PublicKey with KeyIdentifier {} ", keyIdentifier);

        final PublicKey publicKey = keyAccessProviderManager.getPublicKey(keyIdentifier);

        LOGGER.debug("PublicKey returned");

        return publicKey;
    }

    @Override
    public X509Certificate signCertificate(final KeyIdentifier keyIdentifier, final String signatureAlgorithm,
            final X509v3CertificateBuilderHolder certificateBuilder, final X500Principal issuerDN)
            throws CertificateSignatureException, InvalidCertificateExtensionsException, KeyAccessProviderServiceException,
            KeyIdentifierNotFoundException {

        LOGGER.debug("Sign Certificate with X509v3CertificateBuilder {} ,SignatureAlgorithm {}  and KeyIdentifier {} ", certificateBuilder,
                signatureAlgorithm, keyIdentifier);

        final X509Certificate x509Certificate = keyAccessProviderManager.signCertificate(keyIdentifier, signatureAlgorithm, certificateBuilder, issuerDN);

        LOGGER.debug("Certificate Signed Sucessfully.");

        return x509Certificate;
    }

    @Override
    public X509CRLHolder signCRL(final KeyIdentifier keyIdentifier, final String signatureAlgorithm, final X509v2CRLBuilderHolder crlBuilder, final X500Principal issuerDN)
            throws InvalidCRLExtensionsException,
            KeyAccessProviderServiceException, KeyIdentifierNotFoundException, SignCRLException {

        LOGGER.debug("Sign CRL with X509v2CRLBuilder {} ,signatureAlgorithm {} and KeyIdentifier {} ", crlBuilder, signatureAlgorithm, keyIdentifier);

        final X509CRLHolder x509CRLHolder = keyAccessProviderManager.signCRL(keyIdentifier, signatureAlgorithm, crlBuilder, issuerDN);

        LOGGER.debug("Signed CRL Sucessfully ");

        return x509CRLHolder;
    }

    @Override
    public void updateKeyPairStatus(final KeyIdentifier keyIdentifier, final KeyPairStatus keyPairStatus) throws KeyAccessProviderServiceException,
            KeyIdentifierNotFoundException,
            NotSupportedException {

        LOGGER.debug("Update KeyIdentifier status with keyIdentifier {} and keyPairStatus {} ", keyIdentifier, keyPairStatus);

        keyAccessProviderManager.updateKeyPairStatus(keyIdentifier, keyPairStatus);

        systemRecorder.recordSecurityEvent(KEY_ACCESS_PROVIDER_SERVICE, KEY_ACCESS_PROVIDER_MANAGER_BEAN, "key pair status changed to "
                + keyPairStatus, "KAPS.UPDATE_KEYPAIR_STATUS",
                ErrorSeverity.INFORMATIONAL, SUCCESS);

        LOGGER.debug("KeyIdentifier Updated with given status");

    }

    @Override
    public PKCS10CertificationRequestHolder generateCSR(final KeyIdentifier keyIdentifier, final String signatureAlgorithm, final String subject,
            final List<CertificateExtensionHolder> attributes)
            throws CSRGenerationException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        LOGGER.info("Generate CSR with Subject {}, signatureAlgorithm {} and KeyIdentifier {} ", subject, signatureAlgorithm, keyIdentifier);

        final PKCS10CertificationRequestHolder certificationRequestHolder =
                keyAccessProviderManager.generateCSR(keyIdentifier, signatureAlgorithm, subject, attributes);

        LOGGER.info("CSR generated in kaps ");

        systemRecorder.recordSecurityEvent(KEY_ACCESS_PROVIDER_SERVICE, KEY_ACCESS_PROVIDER_MANAGER_BEAN, "CSR generated for " + subject,
                "KAPS.GENERATE_CSR_WITH_ATTRIBUTES",
                ErrorSeverity.INFORMATIONAL, SUCCESS);

        return certificationRequestHolder;
    }
}
