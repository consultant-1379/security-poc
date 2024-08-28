/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class TestHelper {

    /**
     * Generates a key pair
     *
     * @param keyPairAlgorithm
     * @param KeySize
     * @return
     *
     * @throws NoSuchAlgorithmException
     *             Throws in case of algorithm is invalid.
     */
    public static KeyPair generateKeyPair(final String keyPairAlgorithm, final int KeySize) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        final KeyPairGenerator gen = KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(KeySize);
        return gen.generateKeyPair();
    }

    public static X509Certificate issueSelfSignedCertificate(final KeyPair keypair, final X500Name dnName, final String signatureAlgorithm) {

        X509Certificate cert = null;
        final Date validityBeginDate = new Date(System.currentTimeMillis() - 24L * 60L * 60L * 1000L);

        final Date validityEndDate = new Date(System.currentTimeMillis() + (365 * 24L * 60L * 60L * 1000L));

        try {

            final byte[] encoded = keypair.getPublic().getEncoded();
            final SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));

            final X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(dnName, BigInteger.valueOf(System.currentTimeMillis()), validityBeginDate, validityEndDate, dnName,
                    subjectPublicKeyInfo);

            final ContentSigner sigGen = new JcaContentSignerBuilder(signatureAlgorithm).setProvider("BC").build(keypair.getPrivate());
            final X509CertificateHolder certHolder = certGen.build(sigGen);
            cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
        } catch (final Exception e2) {
            e2.printStackTrace();
        }
        return cert;
    }
}
