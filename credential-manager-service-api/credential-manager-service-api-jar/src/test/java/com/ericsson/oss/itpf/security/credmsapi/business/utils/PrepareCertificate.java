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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.CRLReason;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.oss.iptf.security.credmsapi.test.utils.X509CertificateGenerator;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtensionImpl;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CsrHandler;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateExtensions;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509CRL;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;

public class PrepareCertificate {

    @SuppressWarnings("static-access")
    public static X509Certificate prepareCertificate(final KeyPair keyPair) {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final X509CertificateGenerator certGen = new X509CertificateGenerator();

        final String signatureAlgorithmString = "SHA256WithRSAEncryption";
        final PKCS10CertificationRequest pkcs10Csr = PrepareCertificate.prepareCsr(keyPair, signatureAlgorithmString);

        return (certGen.generateCertificate(keyPair, pkcs10Csr, signatureAlgorithmString));

    }

    @SuppressWarnings("static-access")
    public static X509Certificate prepareExpiredCertificate(final KeyPair keyPair) {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final X509CertificateGenerator certGen = new X509CertificateGenerator();

        final String signatureAlgorithmString = "SHA256WithRSAEncryption";
        final PKCS10CertificationRequest pkcs10Csr = PrepareCertificate.prepareCsr(keyPair, signatureAlgorithmString);

        return (certGen.generateExpiredCertificate(keyPair, pkcs10Csr, signatureAlgorithmString));

    }

    @SuppressWarnings("static-access")
    public static X509Certificate prepareNotYetValidCertificate(final KeyPair keyPair) {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final X509CertificateGenerator certGen = new X509CertificateGenerator();

        final String signatureAlgorithmString = "SHA256WithRSAEncryption";
        final PKCS10CertificationRequest pkcs10Csr = PrepareCertificate.prepareCsr(keyPair, signatureAlgorithmString);

        return (certGen.generateNotYetValidCertificate(keyPair, pkcs10Csr, signatureAlgorithmString));

    }

    @SuppressWarnings("static-access")
    public static X509Certificate prepareNearExpiringCertificate(final KeyPair keyPair) {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final X509CertificateGenerator certGen = new X509CertificateGenerator();

        final String signatureAlgorithmString = "SHA256WithRSAEncryption";
        final PKCS10CertificationRequest pkcs10Csr = PrepareCertificate.prepareCsr(keyPair, signatureAlgorithmString);

        return (certGen.generateNearExpiringCertificate(keyPair, pkcs10Csr, signatureAlgorithmString));

    }

    /**
     * @return
     */
    public static KeyPair createKeyPair() {
        KeyPair keyPair;
        keyPair = KeyGenerator.getKeyPair("RSA", 2048);
        return keyPair;
    }

    /**
     * prepareProfileInfoEntity
     *
     * @return
     */
    public static CredentialManagerProfileInfo prepareProfileInfo() {

        //prepare data for Profile
        final CredentialManagerProfileInfo mockProfile = new CredentialManagerProfileInfo();
        final CredentialManagerAlgorithm mockKeyPairAlgorithm = new CredentialManagerAlgorithm();
        final CredentialManagerAlgorithm mockSignaturePairAlgorithm = new CredentialManagerAlgorithm();
        final CredentialManagerCertificateExtensions mockExtentionAttributes = new CredentialManagerCertificateExtensions();
        final CredentialManagerCertificateExtensionImpl mockCertificateExtension = new CredentialManagerCertificateExtensionImpl();
        mockCertificateExtension.setSubjectAlternativeName("ipaddress=1.1.1.1");
        final CredentialManagerSubject subjectByProfile = new CredentialManagerSubject();
        mockProfile.setSubjectByProfile(subjectByProfile);
        mockProfile.setIssuerName("C=Unknown, ST=Unknown, L=Unknown, O=ericsson, OU=ericsson, CN=rootCA");
        mockProfile.setKeyPairAlgorithm(mockKeyPairAlgorithm);
        mockProfile.setSignatureAlgorithm(mockSignaturePairAlgorithm);
        mockSignaturePairAlgorithm.setName("SHA256WithRSAEncryption");
        //mockSignaturePairAlgorithm.setId(22);
        mockSignaturePairAlgorithm.setKeySize(2048);
        mockProfile.setExtentionAttributes(mockExtentionAttributes);
        mockProfile.getKeyPairAlgorithm().setName("RSA");
        mockProfile.getKeyPairAlgorithm().setId(22);
        mockProfile.getKeyPairAlgorithm().setKeySize(2048);

        return mockProfile;
    }

    /**
     * prepareEntity
     *
     * @return
     */
    public static CredentialManagerEntity prepareEntity() {

        final CredentialManagerEntity endEntity = new CredentialManagerEntity();

        final List<String> subAltNameList = new ArrayList<String>();
        subAltNameList.add("ipaddress=1.1.1.1");
        final CredentialManagerSubjectAltName cmAltSubName = new CredentialManagerSubjectAltName();
        cmAltSubName.setIPAddress(subAltNameList);
        endEntity.setSubjectAltName(cmAltSubName);
        endEntity.setEntityProfileName("TOREndEntityProfile");
        //endEntity.setOTP(KeyGenerator.randomPassword(8).toString());
        final CredentialManagerSubject subject = new CredentialManagerSubject();
        // subject.setDnQualifier("CN=altro");
        subject.setCommonName("CN=altro");
        endEntity.setSubject(subject);
        endEntity.setName("myEntity");
        final CredentialManagerSubject issuerDN = new CredentialManagerSubject();
        issuerDN.updateFromSubjectDN("C=Unknown, ST=Unknown, L=Unknown, O=ericsson, OU=ericsson, CN=rootCA");
        endEntity.setIssuerDN(issuerDN);

        //        //prepare data for Entity
        //        final CredentialManagerEntity mockEntityInfo = new CredentialManagerEntity();
        //        final CredentialManagerAlgorithm mockKeyGenerationAlgorithm = new CredentialManagerAlgorithm();
        //        final CredentialManagerSubject mockSubject = new CredentialManagerSubject();
        //        final CredentialManagerSubjectAltName mockSubjectAltName = new CredentialManagerSubjectAltName();
        //        mockEntityInfo.setEntityProfileName("entityProfileName");
        //        mockEntityInfo.setName("entityName");
        //        mockEntityInfo.setKeyGenerationAlgorithm(mockKeyGenerationAlgorithm);
        //        mockEntityInfo.setSubject(mockSubject);
        //        mockEntityInfo.setSubjectAltName(mockSubjectAltName);

        return endEntity;
    }

    /**
     *
     * @param keyPair
     * @param signatureAlgorithmString
     * @return
     */
    public static PKCS10CertificationRequest prepareCsr(final KeyPair keyPair, final String signatureAlgorithmString) {

        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();

        Map<String, Attribute> attributes;
        Attribute[] derAttributes = null;
        final CsrHandler csrHandler = new CsrHandler();
        PKCS10CertificationRequest pkcs10Csr = null;
        // X509Certificate cert = null;
        // CredentialWriterFactory cwf = new CredentialWriterFactory();

        final CredentialManagerEntity endEntity = PrepareCertificate.prepareEntity();

        /*
         * Create extension parameters : only SubjectAletrnativename
         */
        subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAlternateNameImpl credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);
        attributes = new HashMap<String, Attribute>();
        attributes.put(Extension.subjectAlternativeName.toString(), credMsubjAltName.getAttribute());
        final Attribute[] att = new Attribute[1];
        attributes.values().toArray(att);
        derAttributes = att;

        try {
            pkcs10Csr = csrHandler.getCSR(endEntity, signatureAlgorithmString, keyPair, derAttributes);
        } catch (final IssueCertificateException e) {

            e.printStackTrace();
            assertTrue("prepareCertificate: getCSR failed", false);
        }
        return pkcs10Csr;

    } // end prepareCsr

    /**
     * @return
     */
    public static CredentialManagerTrustMaps prepareTrust() {

        final X509Certificate caCert = PrepareCertificate.prepareCertificate();

        X509Certificate caCertWrapped = null;
        try {
            final X509CertificateHolder certificateHolder = new X509CertificateHolder(caCert.getEncoded());
            caCertWrapped = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

        } catch (CertificateException | IOException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
            assertTrue("prepareTrust: X509Certificate failed", false);
        }

        if (caCertWrapped == null) {
            assertTrue("prepareTrust: caCertWrapped is null", false);
        }

        final CredentialManagerCertificateAuthority ca = new CredentialManagerCertificateAuthority(new X500Name("C=AU, ST=Victoria"), "AU");
        try {
            ca.add(caCertWrapped);
        } catch (final CertificateEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            assertTrue("prepareTrust: ca.add(caCertWrapped) failed", false);
        }

        final CredentialManagerTrustMaps caMaps = new CredentialManagerTrustMaps();

        caMaps.getInternalCATrustMap().put("pippo", ca);

        caMaps.getExternalCATrustMap().put("pluto", ca);

        return caMaps;

    } // end prepareTrust

    public static CredentialManagerTrustMaps prepareTrustChain() {

        final X509Certificate caCert = PrepareCertificate.prepareCertificate();

        X509Certificate caCertWrapped = null;
        try {
            final X509CertificateHolder certificateHolder = new X509CertificateHolder(caCert.getEncoded());
            caCertWrapped = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

        } catch (CertificateException | IOException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
            assertTrue("prepareTrust: X509Certificate failed", false);
        }

        if (caCertWrapped == null) {
            assertTrue("prepareTrust: caCertWrapped is null", false);
        }

        final CredentialManagerCertificateAuthority ca = new CredentialManagerCertificateAuthority(new X500Name("C=AU, ST=Victoria"), "AU");
        try {
            ca.add(caCertWrapped);
            ca.add(caCertWrapped);
        } catch (final CertificateEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            assertTrue("prepareTrust: ca.add(caCertWrapped) failed", false);
        }

        final CredentialManagerTrustMaps caMaps = new CredentialManagerTrustMaps();

        caMaps.getInternalCATrustMap().put("pippo", ca);

        caMaps.getExternalCATrustMap().put("pluto", ca);

        return caMaps;

    } // end prepareTrust

    public static CredentialManagerTrustMaps prepareTrustWithInactive() {

        final X509Certificate caCert = PrepareCertificate.prepareCertificate();

        X509Certificate caCertWrapped = null;
        try {
            final X509CertificateHolder certificateHolder = new X509CertificateHolder(caCert.getEncoded());
            caCertWrapped = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

        } catch (CertificateException | IOException e2) {
            // TODO Auto-generated catch block
            e2.printStackTrace();
            assertTrue("prepareTrust: X509Certificate failed", false);
        }

        if (caCertWrapped == null) {
            assertTrue("prepareTrust: caCertWrapped is null", false);
        }

        final CredentialManagerCertificateAuthority ca = new CredentialManagerCertificateAuthority(new X500Name("C=AU, ST=Victoria"), "AU");
        try {
            ca.add(caCertWrapped);
            ca.add(caCertWrapped);
            ca.add(caCertWrapped);
            ca.add(caCertWrapped);
            ca.add(caCertWrapped);
        } catch (final CertificateEncodingException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
            assertTrue("prepareTrust: ca.add(caCertWrapped) failed", false);
        }

        final CredentialManagerTrustMaps caMaps = new CredentialManagerTrustMaps();

        caMaps.getInternalCATrustMap().put("pippo", ca);

        caMaps.getExternalCATrustMap().put("pluto", ca);

        return caMaps;

    } // end prepareTrust

    public static X509Certificate prepareCertificate() {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final CredentialManagerEntity endEntity = new CredentialManagerEntity();
        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
        KeyPair keyPair = null;
        final String signatureAlgorithmString = "SHA256WithRSAEncryption";
        Map<String, Attribute> attributes;
        Attribute[] derAttributes = null;
        final CsrHandler csrHandler = new CsrHandler();
        PKCS10CertificationRequest pkcs10Csr = null;
        final X509CertificateGenerator certGen = new X509CertificateGenerator();
        // X509Certificate cert = null;
        // CredentialWriterFactory cwf = new CredentialWriterFactory();

        final List<String> subAltNameList = new ArrayList<String>();
        subAltNameList.add("ipaddress=1.1.1.1");
        final CredentialManagerSubjectAltName cmAltSubName = new CredentialManagerSubjectAltName();
        cmAltSubName.setIPAddress(subAltNameList);

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        // subject.setDnQualifier("CN=altro");
        subject.setCommonName("CN=altro");

        endEntity.setSubjectAltName(cmAltSubName);
        endEntity.setEntityProfileName("TOREndEntityProfile");
        //endEntity.setOTP(KeyGenerator.randomPassword(8).toString()); forse da sostituire con keyGenerationAlgorithm ???
        endEntity.setSubject(subject);

        /*
         * Create KeyPair parameter
         */
        keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        /*
         * Create extension parameters : only SubjectAletrnativename
         */
        subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAlternateNameImpl credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);
        attributes = new HashMap<String, Attribute>();
        attributes.put(X509Extensions.SubjectAlternativeName.toString(), credMsubjAltName.getAttribute());
        final Attribute[] att = new Attribute[1];
        attributes.values().toArray(att);
        derAttributes = att;

        try {
            pkcs10Csr = csrHandler.getCSR(endEntity, signatureAlgorithmString, keyPair, derAttributes);
        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            assertTrue("prepareCertificate: getCSR failed", false);
        }

        return (certGen.generateCertificate(keyPair, pkcs10Csr, signatureAlgorithmString));
    } // end prepareCertificate

    /**
     * Create an Internal and External map containing both only one CRL
     */
    public static CredentialManagerCrlMaps generateCrl() {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            final Date thisUpdate = new Date(System.currentTimeMillis());
            final Date nextUpdate = new Date(System.currentTimeMillis() + (10 * 24L * 60L * 60L * 1000L));

            final X500Name issuerName = new X500Name("CN=pippo");
            final X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, thisUpdate);

            /*
             * Create KeyPair parameter
             */
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

            crlGen.setNextUpdate(nextUpdate);
            crlGen.addCRLEntry(BigInteger.ONE, thisUpdate, CRLReason.PRIVILEGE_WITHDRAWN.ordinal());
            crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(3547)));
            final ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider("BC").build(keyPair.getPrivate());
            final X509CRLHolder crlHolder = crlGen.build(sigGen);

            final CredentialManagerX509CRL crl = new CredentialManagerX509CRL(crlHolder.getEncoded());

            final CredentialManagerCrlMaps crlMaps = new CredentialManagerCrlMaps();

            crlMaps.getInternalCACrlMap().put("pippo", crl);
            crlMaps.getExternalCACrlMap().put("pluto", crl);

            return crlMaps;

        } catch (final Exception e) {
            assertTrue("generateCrl failed!", false);
        }
        return null;

    } // end generateCrl

    /**
     * Create an Internal map containing only one CRL
     */
    public static CredentialManagerCrlMaps generateInternalCrl() {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            final Date thisUpdate = new Date(System.currentTimeMillis());
            final Date nextUpdate = new Date(System.currentTimeMillis() + (10 * 24L * 60L * 60L * 1000L));

            final X500Name issuerName = new X500Name("CN=pippo");
            final X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, thisUpdate);

            /*
             * Create KeyPair parameter
             */
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

            crlGen.setNextUpdate(nextUpdate);
            crlGen.addCRLEntry(BigInteger.ONE, thisUpdate, CRLReason.PRIVILEGE_WITHDRAWN.ordinal());
            crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(3547)));
            final ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider("BC").build(keyPair.getPrivate());
            final X509CRLHolder crlHolder = crlGen.build(sigGen);

            final CredentialManagerX509CRL crl = new CredentialManagerX509CRL(crlHolder.getEncoded());

            final CredentialManagerCrlMaps crlMaps = new CredentialManagerCrlMaps();

            crlMaps.getInternalCACrlMap().put("pippo", crl);

            return crlMaps;

        } catch (final Exception e) {
            assertTrue("generateCrl failed!", false);
        }
        return null;

    } // end generateCrl

    /**
     * Create an Internal map containing only one CRL
     */
    public static CredentialManagerCrlMaps generateExpiredInternalCrl() {
        {
            Security.addProvider(new BouncyCastleProvider());
        }

        try {
            final Date thisUpdate = new Date(System.currentTimeMillis() - (365 * 86400000L));
            final Date nextUpdate = new Date(System.currentTimeMillis() - 24L * 60L * 60L * 1000L);

            final X500Name issuerName = new X500Name("CN=pippo");
            final X509v2CRLBuilder crlGen = new X509v2CRLBuilder(issuerName, thisUpdate);

            /*
             * Create KeyPair parameter
             */
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);

            crlGen.setNextUpdate(nextUpdate);
            crlGen.addCRLEntry(BigInteger.ONE, thisUpdate, CRLReason.PRIVILEGE_WITHDRAWN.ordinal());
            crlGen.addExtension(X509Extensions.CRLNumber, false, new CRLNumber(BigInteger.valueOf(3547)));
            final ContentSigner sigGen = new JcaContentSignerBuilder("SHA256WITHRSAENCRYPTION").setProvider("BC").build(keyPair.getPrivate());
            final X509CRLHolder crlHolder = crlGen.build(sigGen);

            final CredentialManagerX509CRL crl = new CredentialManagerX509CRL(crlHolder.getEncoded());

            final CredentialManagerCrlMaps crlMaps = new CredentialManagerCrlMaps();

            crlMaps.getInternalCACrlMap().put("pippo", crl);

            return crlMaps;

        } catch (final Exception e) {
            assertTrue("generateCrl failed!", false);
        }
        return null;

    } // end generateExpiredCrl

} // end of PrepareCertificate
