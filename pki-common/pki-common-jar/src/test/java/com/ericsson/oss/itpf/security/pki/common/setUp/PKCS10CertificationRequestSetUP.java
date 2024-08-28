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
package com.ericsson.oss.itpf.security.pki.common.setUp;

import java.io.IOException;
import java.security.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * This class is used to set up test data required for other Junit Test cases.
 * 
 * @author tcshepa
 * 
 */
public class PKCS10CertificationRequestSetUP {

    /**
     * Method to generate valid CSR.
     * 
     * @param keyPairAlgorithm
     * @param signatureAlgorithm
     * @param subject
     * @return returns generated PKCS10CertificationRequest object.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public PKCS10CertificationRequest generateCSR(String keyPairAlgorithm, final String signatureAlgorithm, final X500Name subject) throws NoSuchAlgorithmException, InvalidKeyException,
            SignatureException, IOException {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(1024);
        final KeyPair keyPair = gen.generateKeyPair();

        ASN1ObjectIdentifier attrType = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;
        ASN1Set attrValues = new DERSet(new DERPrintableString("2ER13SA32SAD2G3"));
        ASN1Encodable otp = new Attribute(attrType, attrValues);
        ASN1Set attributes = new DERSet(otp);
        final CertificationRequestInfo certificationRequestInfo = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()), attributes);
        final Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(keyPair.getPrivate());
        signature.update(certificationRequestInfo.getEncoded(ASN1Encoding.DER));
        return new PKCS10CertificationRequest(new CertificationRequest(certificationRequestInfo, new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm), new DERBitString(
                signature.sign())));
    }

    /**
     * Method to generate CSR with invalid attribute type for the challenge password.
     * 
     * @param keyPairAlgorithm
     * @param signatureAlgorithm
     * @param subject
     * @return returns generated PKCS10CertificationRequest object.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public PKCS10CertificationRequest generateCSRWithInvalidAttribute(String keyPairAlgorithm, final String signatureAlgorithm, final X500Name subject) throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException, IOException {
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(1024);
        final KeyPair keyPair = gen.generateKeyPair();

        ASN1ObjectIdentifier attrType = PKCSObjectIdentifiers.pkcs_9_at_challengePassword;

        ASN1Set attrValues = new DERSet(new DERBitString(1));
        ASN1Encodable otp = new Attribute(attrType, attrValues);
        ASN1Set attributes = new DERSet(otp);
        final CertificationRequestInfo certificationRequestInfo = new CertificationRequestInfo(subject, SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()), attributes);
        final Signature signature = Signature.getInstance(signatureAlgorithm);
        signature.initSign(keyPair.getPrivate());
        signature.update(certificationRequestInfo.getEncoded(ASN1Encoding.DER));
        return new PKCS10CertificationRequest(new CertificationRequest(certificationRequestInfo, new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm), new DERBitString(
                signature.sign())));
    }

}
