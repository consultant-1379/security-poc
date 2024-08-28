package com.ericsson.oss.itpf.security.pki.common.test.certificates;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.test.constants.Constants;

public class CertDataHolder {

    private static final Logger logger = LoggerFactory.getLogger(CertDataHolder.class);

    private Certificate certificate;
    private KeyPair keyPair;
    final private List<Certificate> additionalCertificates;

    public Certificate getCert() {
        return certificate;
    }

    public void setCert(final Certificate cert) {
        this.certificate = cert;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(final KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public CertDataHolder(final Certificate cert, final KeyPair keyPair) {
        this.certificate = cert;
        this.keyPair = keyPair;
        this.additionalCertificates = new ArrayList<Certificate>();
    }

    public void addAdditionalCert(final java.security.cert.Certificate certificate) throws CertificateEncodingException {
        additionalCertificates.add(org.bouncycastle.asn1.x509.Certificate.getInstance(certificate.getEncoded()));
    }

    public void setAdditionalCerts(final Collection<Certificate> certlist) {
        additionalCertificates.clear();
        for (final Certificate cert : certlist) {
            additionalCertificates.add(cert);
        }
    }

    public void setAdditionalCerts(final java.security.cert.Certificate[] certarray) throws CertificateEncodingException {
        additionalCertificates.clear();
        for (final java.security.cert.Certificate cert : certarray) {
            additionalCertificates.add(org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded()));
        }
    }

    public List<Certificate> getAdditionalCertificates() {
        return additionalCertificates;
    }

    public CMPCertificate[] getExtraCerts() {
        CMPCertificate[] result = new CMPCertificate[additionalCertificates.size()];
        for (int index = 0; index < additionalCertificates.size(); index++) {
            result[index] = new CMPCertificate(additionalCertificates.get(index));
        }
        return result;
    }

    public static CertDataHolder getRACertDataHolder(final String filePath) {
        CertDataHolder certDataHolder = null;
        FileInputStream fileInputStream = null;
        try {
            final KeyStore keyStore = KeyStore.getInstance(Constants.JKS_KEYSTORE_TYPE);
            fileInputStream = new FileInputStream(new File(filePath));
            keyStore.load(fileInputStream, new String(new byte[] { 115, 101, 99, 109, 103, 109, 116 }).toCharArray());

            final PrivateKey key = (PrivateKey) keyStore.getKey(Constants.KEYSTORE_ALIAS, new String(new byte[] { 115, 101, 99, 109, 103, 109, 116 }).toCharArray());
            final X509Certificate cert = (X509Certificate) keyStore.getCertificateChain(Constants.KEYSTORE_ALIAS)[0];
            final KeyPair keyPair = new KeyPair(cert.getPublicKey(), key);
            certDataHolder = new CertDataHolder(Certificate.getInstance(cert.getEncoded()), keyPair);

            final java.security.cert.Certificate[] additionalCerts = keyStore.getCertificateChain(Constants.KEYSTORE_ALIAS);
            for (final java.security.cert.Certificate additionalCert : additionalCerts) {
                certDataHolder.addAdditionalCert(additionalCert);
            }

        } catch (Exception exception) {
            logger.error("Exception occured in getRACertDataHolder method {}", exception);
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    logger.error("Exception occured while closing the FileInputStream in getRACertDataHolder method {}", e);
                }
            }
        }
        return certDataHolder;
    }
}
