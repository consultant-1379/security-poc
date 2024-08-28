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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;

/**
 * This class was created because X509Certificate is not serializable properly.
 */

public class CredentialManagerX509Certificate implements Serializable {
    static
    {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }
    
    private static final long serialVersionUID = -5195207296537485229L;

    private transient X509Certificate wrapped;
    private final byte[] certBytes;

    public byte[] getCertBytes() {
        return certBytes;
    }

    /**
     * Constructs an CredentialManagerX509Certificate object instance
     * 
     * @param cert
     * @throws CertificateEncodingException
     */
    public CredentialManagerX509Certificate(final X509Certificate cert) throws CertificateEncodingException {
        this.wrapped = cert;
        this.certBytes = cert.getEncoded();
    }

    public CredentialManagerX509Certificate(final byte[] certBytes) throws CertificateEncodingException {
        this.certBytes = certBytes;
        try {
            //this.wrapped = new X509Certificate(certBytes);
            final X509CertificateHolder certificateHolder = new X509CertificateHolder(certBytes);
            this.wrapped = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);
        } catch (CertificateException | IOException e) {
            throw new CertificateEncodingException(e);
        }
    }

    /**
     * Gets the certificate. This object is NOT serializable.
     * 
     * @return cert
     */
    public X509Certificate retrieveCertificate() {
        return wrapped;
    }

    private void readObject(final ObjectInputStream ois) throws IOException, ClassNotFoundException, CertificateException {
        ois.defaultReadObject();
        //        this.wrapped = new X509Certificate(certBytes);
        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certBytes);
        this.wrapped = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certificateHolder);

    }

    private void writeObject(final ObjectOutputStream oos) throws IOException {
        oos.defaultWriteObject();
    }
}
