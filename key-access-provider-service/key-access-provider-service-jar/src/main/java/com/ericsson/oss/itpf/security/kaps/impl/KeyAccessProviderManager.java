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
package com.ericsson.oss.itpf.security.kaps.impl;

import java.io.IOException;
import java.security.*;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.builder.*;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.*;
import com.ericsson.oss.itpf.security.kaps.common.Constants;
import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.common.utils.SignerUtility;
import com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException;
import com.ericsson.oss.itpf.security.kaps.crl.exception.SignCRLException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.exception.NotSupportedException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.kaps.model.holder.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;

/**
 * Class for all the key related operations {@link KeyAccessProviderService}
 *
 * @author tcsrcho
 *
 */
public class KeyAccessProviderManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyAccessProviderManager.class);
    private static final String FAILURE = "FAILURE";
    private static final String KEY_ACCESS_PROVIDER_SERVICE = "Key Access Provider Service";

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Inject
    CSRBuilder csrBuilder;

    @Inject
    CertificateBuilder certificateBuilder;

    @Inject
    CRLBuilder crlBuilder;

    @Inject
    SignerUtility signerUtility;

    /**
     * Generates key pair with given algorithm and modulus.
     *
     * @param algorithm
     *            Name of the algorithm
     * @param modulus
     *            Key size
     *
     * @return {@link KeyIdentifier} object.
     *
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     *
     * @throws KeyPairGenerationException
     *             Thrown in case of any failures while generating key pair.
     *
     */
    public KeyIdentifier generateKeyPair(final String algorithm, final int modulus) throws KeyAccessProviderServiceException,
            KeyPairGenerationException {

        try {
            final KeyPair keyPair = createKeyPair(algorithm, modulus);
            final KeyIdentifier keyIdentifier = keyPairPersistenceHandler.saveKeyPair(algorithm, modulus, keyPair);
            return keyIdentifier;
        } catch (KeyPairGenerationException keyGenerateException) {
            systemRecorder.recordSecurityEvent(KEY_ACCESS_PROVIDER_SERVICE, "Keypair generation failure for CA",
                    " Unable to generate keypair for the CA", "CERTIFICATE.GENERATE_CERTIFICATE", ErrorSeverity.ERROR, FAILURE);
            LOGGER.error(keyGenerateException.getMessage(), keyGenerateException);
            throw keyGenerateException;
        }
    }

    /**
     * Gets the public key using its key identifier.
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     *
     * @return The PublicKey Object
     *
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case of KeyIdentifier not found.
     */
    public PublicKey getPublicKey(final KeyIdentifier keyIdentifier) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        return keyPairPersistenceHandler.getPublicKey(keyIdentifier);
    }

    /**
     * Generate the CSR for given subject with given attributes by signing with given signature algorithm using private key of provided keyIdentifier.
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param signatureAlgorithm
     *            Algorithm used to sign CSR.
     * @param subject
     *            subject dn
     * @param attributes
     *            list of extensions serialized and passed as attributes.
     * @return PKCS10CertificationRequestHolder Object.
     * @throws CSRGenerationException
     *             Thrown in case of any failures while generating the CSR.
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case of KeyIdentifier not found.
     *
     *
     */
    public PKCS10CertificationRequestHolder generateCSR(final KeyIdentifier keyIdentifier, final String signatureAlgorithm, final String subject,
            final List<CertificateExtensionHolder> attributes) throws CSRGenerationException, KeyAccessProviderServiceException,
            KeyIdentifierNotFoundException {

        try {
            final PKCS10CertificationRequest pkcs10CertificationRequest = csrBuilder.buildPKCS10CertificationRequest(keyIdentifier,
                    signatureAlgorithm, new X500Name(subject), attributes);

            final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
            return pkcs10CertificationRequestHolder;
        } catch (IOException ioException) {
            systemRecorder.recordSecurityEvent(KEY_ACCESS_PROVIDER_SERVICE, "Processing of Generate CSR", " Unable to generate CSR",
                    "KAPS.GENERATE_CSR", ErrorSeverity.ERROR, FAILURE);
            LOGGER.error(ErrorMessages.INVALID_CSR_ENCODING, ioException);
            throw new CSRGenerationException(ErrorMessages.INVALID_CSR_ENCODING, ioException);
        }
    }

    /**
     * Sign the Certificate using keyIdentifier, signatureAlgorithm and information provided in x509v3CertificateBuilderHolder object
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param signatureAlgorithm
     *            Algorithm used to sign the CRL
     * @param x509v3CertBuilderHolder
     *            The X509v3CertificateBuilderHolder Object
     * @param issuerDN
     *            The X500Principal Object
     * @return X509Certificate Object
     *
     * @throws CertificateSignatureException
     *             Thrown in case of any failures while signing the certificate.
     * @throws InvalidCertificateExtensionsException
     *             Thrown in case of given certificate extensions are invalid.
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case of KeyIdentifier not found.
     *
     */
    public X509Certificate signCertificate(final KeyIdentifier keyIdentifier, final String signatureAlgorithm,
            final X509v3CertificateBuilderHolder x509v3CertBuilderHolder, final X500Principal issuerDN) throws CertificateSignatureException,
            InvalidCertificateExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        try {
            final X509v3CertificateBuilder x509v3CertificateBuilder = certificateBuilder.buildX509v3CertificateBuilder(x509v3CertBuilderHolder, issuerDN);

            final ContentSigner sigGen = signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm);
            final X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(x509v3CertificateBuilder.build(sigGen));
            LOGGER.debug("Done with certificate signing ");
            return certificate;

        } catch (java.security.cert.CertificateException certificateException) {
            systemRecorder.recordSecurityEvent(KEY_ACCESS_PROVIDER_SERVICE, "X509Certificate generation failure",
                    "Can not get the X509Certificate from X509CertificateBuilder", "CERTIFICATE.GENERATE_CERTIFICATE", ErrorSeverity.ERROR, FAILURE);
            LOGGER.error(ErrorMessages.X509CERTIFICATE_GENERATION_FAILED + certificateException.getMessage(), certificateException);
            throw new CertificateSignatureException(ErrorMessages.X509CERTIFICATE_GENERATION_FAILED);
        } catch (com.ericsson.oss.itpf.security.kaps.common.exception.SignatureException signatureException) {
            LOGGER.error(ErrorMessages.CERTIFICATE_SIGNATURE_GENERATION_FAILED, signatureAlgorithm);
            throw new CertificateSignatureException(ErrorMessages.CERTIFICATE_SIGNATURE_GENERATION_FAILED, signatureException);
        }

    }

    /**
     * Sign the CRL using keyIdentifier, signatureAlgorithm and information provided in x509v2crlBuilderHolder object
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param signatureAlgorithm
     *            Algorithm used to sign the CRL
     * @param x509v2CRLBuilderHolder
     *            The X509v2crlBuilderHolder Object
     * @param issuerDN
     *            The X500Principal Object
     *
     * @return X509CRLHolder object
     *
     * @throws InvalidCRLExtensionsException
     *             is thrown when CRL Extensions are not valid.
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case of KeyIdentifier not found.
     * @throws SignCRLException
     *             is thrown that an exception has occurred during CRL signing
     */
    public X509CRLHolder signCRL(final KeyIdentifier keyIdentifier, final String signatureAlgorithm,
            final X509v2CRLBuilderHolder x509v2CRLBuilderHolder, final X500Principal issuerDN) throws InvalidCRLExtensionsException, KeyAccessProviderServiceException,
            KeyIdentifierNotFoundException, SignCRLException {

        try {
            final X509v2CRLBuilder x509crlBuilder = crlBuilder.buildX509v2CRLBuilder(x509v2CRLBuilderHolder, issuerDN);

            final ContentSigner sigGen = signerUtility.getContentSigner(keyIdentifier, signatureAlgorithm);
            final X509CRL x509CRL = new JcaX509CRLConverter().setProvider(Constants.PROVIDER_NAME).getCRL(x509crlBuilder.build(sigGen));
            final X509CRLHolder x509CRLHolder = new X509CRLHolder();
            x509CRLHolder.setCrlBytes(x509CRL.getEncoded());
            return x509CRLHolder;
        } catch (java.security.cert.CRLException crlException) {
            LOGGER.error(crlException.getMessage(), crlException);
            throw new SignCRLException(ErrorMessages.UNABLE_TO_SIGN_CRL, crlException);
        } catch (com.ericsson.oss.itpf.security.kaps.common.exception.SignatureException signatureException) {
            LOGGER.error(ErrorMessages.CRL_SIGNATURE_GENERATION_FAILED, signatureAlgorithm);
            throw new SignCRLException(ErrorMessages.CRL_SIGNATURE_GENERATION_FAILED, signatureException);
        } catch (Exception exception) {
            LOGGER.error(ErrorMessages.CRL_SIGNATURE_GENERATION_FAILED, exception);
            throw new SignCRLException(ErrorMessages.CRL_SIGNATURE_GENERATION_FAILED, exception);
        }

    }

    /**
     * Updates KeyIdentifier Status from Active to inactive. Vice-versa is not possible.
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param keyPairStatus
     *
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case of KeyIdentifier not found.
     * @throws NotSupportedException
     *             Thrown in case of any unsupported operation was encountered.
     */
    public void updateKeyPairStatus(final KeyIdentifier keyIdentifier, final KeyPairStatus keyPairStatus) throws KeyAccessProviderServiceException,
            KeyIdentifierNotFoundException, NotSupportedException {

        if (keyPairStatus == KeyPairStatus.ACTIVE) {
            LOGGER.error(ErrorMessages.UNSUPPORTED_KEYPAIR_STATUS_OPERATION);
            throw new NotSupportedException(ErrorMessages.UNSUPPORTED_KEYPAIR_STATUS_OPERATION);
        }
        keyPairPersistenceHandler.updateKeyPairInfoStatus(keyIdentifier, keyPairStatus);
    }

    private KeyPair createKeyPair(final String algorithm, final int modulus) throws KeyPairGenerationException {
        KeyPairGenerator keyPairGenerator;

        try {
            keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
            keyPairGenerator.initialize(modulus);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            LOGGER.error(ErrorMessages.KEY_GENERATION_ALGORITHM_IS_NOT_SUPPORTED, noSuchAlgorithmException);
            throw new KeyPairGenerationException(ErrorMessages.KEY_GENERATION_ALGORITHM_IS_NOT_SUPPORTED, noSuchAlgorithmException);
        }

        return keyPairGenerator.generateKeyPair();

    }
}