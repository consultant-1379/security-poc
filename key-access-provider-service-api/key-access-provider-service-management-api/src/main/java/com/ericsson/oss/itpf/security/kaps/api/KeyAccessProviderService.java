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
package com.ericsson.oss.itpf.security.kaps.api;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Remote;
import javax.security.auth.x500.X500Principal;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.*;
import com.ericsson.oss.itpf.security.kaps.crl.exception.*;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.exception.NotSupportedException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.*;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.kaps.model.holder.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;

/**
 * Interface for all the key related operations.
 *
 * The API provides the below operations.
 *
 * <ul>
 * <li>Generation of key pair</li>
 * <li>Retrieval of public key</li>
 * <li>generateCSR</li>
 * <li>signCertificate</li>
 * <li>signCRL</li>
 * <li>updateKeyIdentifierStatus</li>
 * </ul>
 */
@Remote
@EService
public interface KeyAccessProviderService {

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
     * @throws KeyPairGenerationException
     *             Thrown in case of any failures while generating key pair.
     */
    KeyIdentifier generateKeyPair(final String algorithm, final Integer modulus) throws KeyAccessProviderServiceException, KeyPairGenerationException;

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
     *
     */
    PublicKey getPublicKey(final KeyIdentifier keyIdentifier) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException;

    /**
     * Generate the CSR for given subject, attributes which are passed as serializable objects in list and signs using the private key of given keyidentifier and signature algorithm.
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
     */
    PKCS10CertificationRequestHolder generateCSR(final KeyIdentifier keyIdentifier, final String signatureAlgorithm, final String subject, final List<CertificateExtensionHolder> attributes)
            throws CSRGenerationException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException;

    /**
     * Sign the Certificate using keyIdentifier, signatureAlgorithm and information provided in x509v3CertificateBuilderHolder object
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param signatureAlgorithm
     *            Algorithm used to sign the CRL
     * @param x509v3CertificateBuilderHolder
     *            The X509v3CertificateBuilderHolder Object
     * @param issuerDN
     *            The issuerDN of Certificate
     *
     * @return X509Certificate Object
     *
     * @throws CertificateSignatureException
     *             Indicate that Certificate signing has failed during Certificate generation.
     *
     * @throws InvalidCertificateExtensionsException
     *             Thrown in case of given certificate extensions are invalid.
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case of KeyIdentifier not found.
     */
    X509Certificate signCertificate(final KeyIdentifier keyIdentifier, final String signatureAlgorithm, final X509v3CertificateBuilderHolder x509v3CertificateBuilderHolder, final X500Principal issuerDN)
            throws CertificateSignatureException, InvalidCertificateExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException;

    /**
     * Sign the CRL using keyIdentifier, signatureAlgorithm and information provided in x509v2crlBuilderHolder object
     *
     * @param keyIdentifier
     *            Key identifier object for retrieving keys.
     * @param signatureAlgorithm
     *            Algorithm used to sign the CRL
     * @param x509v2crlBuilderHolder
     *            The X509v2crlBuilderHolder Object
     * @param issuerDN
     *            The issuerDN of certificate
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
    X509CRLHolder signCRL(final KeyIdentifier keyIdentifier, final String signatureAlgorithm, final X509v2CRLBuilderHolder x509v2crlBuilderHolder, final X500Principal issuerDN)
             throws InvalidCRLExtensionsException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, SignCRLException;

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
    void updateKeyPairStatus(final KeyIdentifier keyIdentifier, final KeyPairStatus keyPairStatus) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NotSupportedException;

}
