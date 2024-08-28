package com.ericsson.oss.itpf.security.pki.common.cmp.client;

import java.security.KeyPair;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Certificate;

public class CertDataHolder {
    private Certificate cert;
    private KeyPair keyPair;
    private List<Certificate> additionalCerts;

    public Certificate getCert() {
        return cert;
    }

    public void setCert(final Certificate cert) {
        this.cert = cert;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public void setKeyPair(final KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public CertDataHolder(final Certificate cert, final KeyPair keyPair) {
        this.cert = cert;
        this.keyPair = keyPair;
        this.additionalCerts = new ArrayList<Certificate>();
    }

    public void addAdditionalCert(java.security.cert.Certificate certificate) throws CertificateEncodingException {

        additionalCerts.add(org.bouncycastle.asn1.x509.Certificate.getInstance(certificate.getEncoded()));
    }

    public List<Certificate> getAdditionalCertificates() {
        return additionalCerts;
    }
}
