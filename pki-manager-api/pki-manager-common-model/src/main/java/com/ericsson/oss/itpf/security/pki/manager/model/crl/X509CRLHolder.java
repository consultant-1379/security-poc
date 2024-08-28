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
package com.ericsson.oss.itpf.security.pki.manager.model.crl;

import java.io.*;
import java.security.Security;
import java.security.cert.*;

import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;

/**
 * This class was created because X509CRL is not serializable properly.
 */

public class X509CRLHolder implements Serializable {

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
     * @throws CRLException
     */
    public X509CRLHolder(final X509CRL crl) throws CRLException {
        this.wrapped = crl;
        this.crlBytes = crl.getEncoded();
    }

    /**
     * Constructs a CredentialManagerX509CRL object instance
     * 
     * @param crlBytes
     * @throws CRLException
     * @throws IOException
     */
    public X509CRLHolder(final byte[] crlBytes) throws CRLException, IOException {
        this.crlBytes = crlBytes;

        //this.wrapped = new X509Certificate(certBytes);
        final org.bouncycastle.cert.X509CRLHolder x509crlHolder = new org.bouncycastle.cert.X509CRLHolder(crlBytes);
        this.wrapped = new JcaX509CRLConverter().setProvider("BC").getCRL(x509crlHolder);

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

        org.bouncycastle.cert.X509CRLHolder x509crlHolder;
        try {
            x509crlHolder = new org.bouncycastle.cert.X509CRLHolder(this.crlBytes);
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
