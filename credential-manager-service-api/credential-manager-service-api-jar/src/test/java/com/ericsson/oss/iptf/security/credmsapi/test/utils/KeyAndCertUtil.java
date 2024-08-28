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

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.handlers.CsrHandler;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerSubjectAlternateNameImpl;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;

public class KeyAndCertUtil {

    public CredentialManagerEntity endEntity = new CredentialManagerEntity();
    public SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType();
    public String signatureAlgorithmString = "SHA256WithRSAEncryption";
    public Map<String, Attribute> attributes;
    public CsrHandler csrHandler = new CsrHandler();
    public X509CertificateGenerator certGen = new X509CertificateGenerator();

    public KeyStore certKeystore;
    public String certStoreName = "src/test/resources/admin-keystore";
    public String certPassword = "password";
    public String certAlias = "admin-cert";
    public java.security.cert.Certificate[] certChain;
    public java.security.cert.Certificate[] CaChain;
    public PrivateKey certPrivateKey;

    public KeyPair keyPair = null;
    public X509Certificate cert = null;
    public PKCS10CertificationRequest pkcs10Csr = null;
    public Attribute[] derAttributes = null;

    public KeyAndCertUtil() {
        this.prepareParameters();
    }

    @SuppressWarnings("static-access")
    public void prepareParameters() {

        /*
         * Prepare parameters to invoke getCsr method of CsrHandler class
         */

        final List<String> subAltNameList = new ArrayList<String>();
        subAltNameList.add("ipaddress=1.1.1.1");
        final CredentialManagerSubjectAltName cmAltSubName = new CredentialManagerSubjectAltName();
        cmAltSubName.setIPAddress(subAltNameList);

        final CredentialManagerSubject subject = new CredentialManagerSubject();
        // subject.setDnQualifier("altro");
        subject.setCommonName("altro");

        this.endEntity.setSubjectAltName(cmAltSubName);
        this.endEntity.setEntityProfileName("TOREndEntityProfile");
        // endEntity.setOTP(KeyGenerator.randomPassword(8).toString());
        this.endEntity.setSubject(subject);

        /*
         * Create KeyPair parameter
         */
        this.keyPair = KeyGenerator.getKeyPair("RSA", 2048);

        /*
         * Create extension parameters : only SubjectAletrnativename
         */
        this.subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAlternateNameImpl credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(this.subjectAltName);
        this.attributes = new HashMap<String, Attribute>();
        this.attributes.put(Extension.subjectAlternativeName.toString(), credMsubjAltName.getAttribute());
        final Attribute[] att = new Attribute[1];
        this.attributes.values().toArray(att);
        this.derAttributes = att;

        try {
            this.pkcs10Csr = this.csrHandler.getCSR(this.endEntity, this.signatureAlgorithmString, this.keyPair, this.derAttributes);
        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        this.cert = this.certGen.generateCertificate(this.keyPair, this.pkcs10Csr, this.signatureAlgorithmString);

        this.certPrivateKey = this.keyPair.getPrivate();

        final Certificate[] chain = new Certificate[2];
        chain[0] = this.cert;

        final Certificate[] caChain = new Certificate[2];
        caChain[0] = this.cert;

        /**
         * Generazione secondo certificato (varia solo il subject)
         */
        subject.setCommonName("questo");
        this.endEntity.setSubject(subject);
        try {
            this.pkcs10Csr = this.csrHandler.getCSR(this.endEntity, this.signatureAlgorithmString, this.keyPair, this.derAttributes);
        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        this.cert = this.certGen.generateCertificate(this.keyPair, this.pkcs10Csr, this.signatureAlgorithmString);

        /**
         * Set chain
         */
        chain[1] = this.cert;
        this.certChain = chain;

        caChain[1] = this.cert;
        this.CaChain = caChain;
    }

    public void prepareCert() {

        FileInputStream fis = null;

        // load the keystore with the previous data (if any)
        final File file = new File(this.certStoreName);
        try {
            this.certKeystore = KeyStore.getInstance(StorageConstants.JKS_STORE_TYPE);
            if (!file.exists()) {
                System.out.println("File " + this.certStoreName + "not found!");
            } else {
                fis = new FileInputStream(file);
                this.certKeystore.load(fis, this.certPassword.toCharArray());
                fis.close();

                this.certChain = this.certKeystore.getCertificateChain(this.certAlias);
                this.certPrivateKey = (PrivateKey) this.certKeystore.getKey(this.certAlias, this.certPassword.toCharArray());
            }
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

    public void prepareCAcert() {

        FileInputStream fis = null;

        // load the keystore with the previous data (if any)
        final File file = new File(this.certStoreName);
        try {
            this.certKeystore = KeyStore.getInstance(StorageConstants.JKS_STORE_TYPE);
            if (!file.exists()) {
                System.out.println("File " + this.certStoreName + "not found!");
            } else {
                fis = new FileInputStream(file);
                this.certKeystore.load(fis, this.certPassword.toCharArray());
                fis.close();
                this.CaChain = this.certKeystore.getCertificateChain(this.certAlias);
                this.certPrivateKey = (PrivateKey) this.certKeystore.getKey(this.certAlias, this.certPassword.toCharArray());
            }
        } catch (final Exception e) {
            e.printStackTrace();
        }
    }

}