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
package com.ericsson.oss.iptf.security.credmsapi.test.utils;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

public class X509CertificateGenerator {

    /**
     * Generation of Valid Certificate (classic usage): valid since yesterday for a year
     * 
     * @param keypair
     * @param pkcs10CertificationRequest
     * @param signatureAlgorith
     * @return
     */
    public static X509Certificate generateCertificate(final KeyPair keypair, final PKCS10CertificationRequest pkcs10CertificationRequest, final String signatureAlgorith) {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        final Date validityBeginDate = new Date(System.currentTimeMillis() - 24L * 60L * 60L * 1000L);

        final Date validityEndDate = new Date(System.currentTimeMillis() + (365 * 86400000L));

        return localGenerateCertificate(keypair, pkcs10CertificationRequest, validityBeginDate, validityEndDate);
    }

    /**
     * Generation of Expired Certificate: valid until yesterday
     * 
     * @param keypair
     * @param pkcs10CertificationRequest
     * @param signatureAlgorith
     * @return
     */
    public static X509Certificate generateExpiredCertificate(final KeyPair keypair, final PKCS10CertificationRequest pkcs10CertificationRequest, final String signatureAlgorith) {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        final Date validityBeginDate = new Date(System.currentTimeMillis() - (365 * 86400000L));

        final Date validityEndDate = new Date(System.currentTimeMillis() - 24L * 60L * 60L * 1000L);

        return localGenerateCertificate(keypair, pkcs10CertificationRequest, validityBeginDate, validityEndDate);
    }

    /**
     * Generation of Not Yet Valid Certificate: valid since next month for a year
     * 
     * @param keypair
     * @param pkcs10CertificationRequest
     * @param signatureAlgorith
     * @return
     */
    public static X509Certificate generateNotYetValidCertificate(final KeyPair keypair, final PKCS10CertificationRequest pkcs10CertificationRequest, final String signatureAlgorith) {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        final Date validityBeginDate = new Date(System.currentTimeMillis() + (30 * 86400000L));

        final Date validityEndDate = new Date(System.currentTimeMillis() + (395 * 86400000L));

        return localGenerateCertificate(keypair, pkcs10CertificationRequest, validityBeginDate, validityEndDate);
    }
    
    /**
     * Generation of Certificate near expiration date: valid until 10 days from now
     * 
     * @param keypair
     * @param pkcs10CertificationRequest
     * @param signatureAlgorith
     * @return
     */
    public static X509Certificate generateNearExpiringCertificate(final KeyPair keypair, final PKCS10CertificationRequest pkcs10CertificationRequest, final String signatureAlgorithm) {
        Security.addProvider(new BouncyCastleProvider());
        
        final Date validityBeginDate = new Date(System.currentTimeMillis() - (365 * 86400000L));

        final Date validityEndDate = new Date(System.currentTimeMillis() + (10 * 86400000L));

        return localGenerateCertificate(keypair, pkcs10CertificationRequest, validityBeginDate, validityEndDate);

    }

    /**
     * @param keypair
     * @param pkcs10CertificationRequest
     * @param validityBeginDate
     * @param validityEndDate
     * @return
     */
    private static X509Certificate localGenerateCertificate(final KeyPair keypair, final PKCS10CertificationRequest pkcs10CertificationRequest, final Date validityBeginDate, final Date validityEndDate) {
        final X500Principal issuerDN = new X500Principal("CN=rootCA, OU=ericsson, O=ericsson, L=Unknown, ST=Unknown, C=Unknown");
        final X500Name issuerName = new X500Name(issuerDN.getName());

        final X500Name dnName = new X500Name(pkcs10CertificationRequest.getSubject().toString());

        final X509v3CertificateBuilder certGen = new X509v3CertificateBuilder(issuerName, BigInteger.valueOf(System.currentTimeMillis()), validityBeginDate, validityEndDate, dnName,
                pkcs10CertificationRequest.getSubjectPublicKeyInfo());

        final PrivateKey privateKey = keypair.getPrivate();

        try {
            addX509Extensions(pkcs10CertificationRequest, certGen);
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        ContentSigner sigGen = null;

        try {
            sigGen = new JcaContentSignerBuilder("SHA256WithRSAEncryption").setProvider("BC").build(privateKey);
            final X509CertificateHolder cert = certGen.build(sigGen);
            return new JcaX509CertificateConverter().setProvider("BC").getCertificate(cert);
        } catch (OperatorCreationException | CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private static void addX509Extensions(final PKCS10CertificationRequest pkcs10CertificationRequest, final X509v3CertificateBuilder certGen) throws IOException {

        final Attribute[] attributes = pkcs10CertificationRequest.getAttributes();

        if (attributes == null) {
            return;
        }
        for (final Attribute attr : attributes) {
            if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                final Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));

                final Enumeration e = extensions.oids();
                while (e.hasMoreElements()) {
                    final ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
                    final Extension ext = extensions.getExtension(oid);
                    certGen.addExtension(oid, ext.isCritical(), ext.getEncoded());
                }
            }
        }
    }
}
