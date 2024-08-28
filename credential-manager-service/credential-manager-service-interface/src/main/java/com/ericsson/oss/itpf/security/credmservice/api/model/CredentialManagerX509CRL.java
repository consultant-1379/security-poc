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
package com.ericsson.oss.itpf.security.credmservice.api.model;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;

import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;

import com.ericsson.oss.itpf.security.credmservice.api.model.exception.CRLEncodingException;

/**
 * This class was created because X509CRL is not serializable properly.
 */

public class CredentialManagerX509CRL implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -8422261591459245794L;

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private transient X509CRL wrapped;
    private final byte[] crlBytes;

    public byte[] getCrlBytes() {
        return crlBytes;
    }

    /**
     * Constructs a CredentialManagerX509CRL object instance
     * 
     * @param crl
     * @throws CRLEncodingException
     */
    public CredentialManagerX509CRL(final X509CRL crl) throws CRLEncodingException {
        this.wrapped = crl;
        try {
            this.crlBytes = crl.getEncoded();
        } catch (final CRLException e) {
            throw new CRLEncodingException("Encoding from X509CRL:", e);
        }
    }

    /**
     * Constructs a CredentialManagerX509CRL object instance
     * 
     * @param crlBytes
     * @throws CRLEncodingException
     */
    public CredentialManagerX509CRL(final byte[] crlBytes) throws CRLEncodingException {
        this.crlBytes = crlBytes;
        try {
            //this.wrapped = new X509Certificate(certBytes);
            final X509CRLHolder x509crlHolder = new X509CRLHolder(crlBytes);
            this.wrapped = new JcaX509CRLConverter().setProvider("BC").getCRL(x509crlHolder);

        } catch (CRLException | IOException e) {
            throw new CRLEncodingException("Encoding from crlBytes:", e);
        }
    }

    /**
     * Gets the crl. This object is NOT serializable.
     * 
     * @return crl
     */
    public X509CRL retrieveCRL() {
        return this.wrapped;
    }
    
    
    /**
     * 
     * @param ois
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws CertificateException
     */
    private void readObject(final ObjectInputStream ois) throws IOException, ClassNotFoundException, CertificateException {
        ois.defaultReadObject();
        
        X509CRLHolder x509crlHolder;
        try {
            x509crlHolder = new X509CRLHolder(this.crlBytes);
            this.wrapped = new JcaX509CRLConverter().setProvider("BC").getCRL(x509crlHolder);
        } catch (CRLException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    /**
     * 
     * @param oos
     * @throws IOException
     */
    private void writeObject(final ObjectOutputStream oos) throws IOException {
        oos.defaultWriteObject();
    }
    

}
