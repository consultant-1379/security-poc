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
package com.ericsson.oss.itpf.security.pki.common.certificatemanagement.builder;

import java.io.IOException;
import java.security.*;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequestInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;

/**
 * This class creates {@link PKCS10CertificationRequest} with all the values like subject, public key and attributes.
 * 
 */
public class CSRBuilder {

    @Inject
    Logger logger;

    /**
     * Generates Certificate Signing Request.
     * 
     * @param subject
     *            {@link X500Name} for which CSR should be generated
     * @param keyPair
     *            {@link KeyPair} for the corresponding subject
     * @param signatureAlgorithm
     *            signature algorithm using which the CSR needs to be generated
     * @param attributes
     *            {@link ASN1Set} attributes for CSR. Attributes can be null if not present
     * @throws InvalidKeyException
     *             Thrown if the key is invalid.
     * @throws IOException
     *             Thrown on BER or a DER encoding error.
     * @throws NoSuchAlgorithmException
     *             Thrown if no Provider supports a Signature implementation for the specified algorithm.
     * @throws SignatureException
     *             Thrown if this signature object is not initialized properly.
     */
    public PKCS10CertificationRequest generatePKCS10Request(final X500Name subject, final KeyPair keyPair, final String signatureAlgorithm, final ASN1Set attributes) throws InvalidKeyException,
            IOException, NoSuchAlgorithmException, SignatureException {
        final String subjectInStringFormat = subject.toString();
        logger.debug("PKCS10Certificate Request generation for {} ", subjectInStringFormat);

        final CertificationRequestInfo certificationRequestInfo = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()), attributes);

        logger.debug("Signature algorithm for CSR is {}", signatureAlgorithm);
        final Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(keyPair.getPrivate());
        signature.update(certificationRequestInfo.getEncoded(ASN1Encoding.DER));

        final AlgorithmIdentifier signatureAlgorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        final CertificationRequest certificationRequest = new CertificationRequest(certificationRequestInfo, signatureAlgorithmIdentifier, new DERBitString(signature.sign()));

        final PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificationRequest);

        return pkcs10CertificationRequest;
    }
}
