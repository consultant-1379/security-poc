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
package com.ericsson.oss.itpf.security.pki.common.model.certificate.request;

import java.io.*;
import java.util.Arrays;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;

/**
 * Holder for PKCS10CertificationRequest request.
 * 
 * @author xprabil
 * 
 */
public class PKCS10CertificationRequestHolder extends AbstractCertificateRequestHolder implements Serializable {

    private static final long serialVersionUID = -5195207296537485229L;

    private transient PKCS10CertificationRequest pKCS10Request;

    private final byte[] pkcs10Request;

    /**
     * 
     * Constructs an PKCS10CertificationRequestHolder object instance.
     * 
     * @param pkcs10CertificationRequest
     *            The pkcs10 certificate request object.
     * 
     * @throws IOException
     *             Throws in case of any io failures.
     * 
     */
    public PKCS10CertificationRequestHolder(final PKCS10CertificationRequest pkcs10CertificationRequest) throws IOException {

        this.pKCS10Request = pkcs10CertificationRequest;

        this.pkcs10Request = pkcs10CertificationRequest.getEncoded();

    }

    /**
     * 
     * Gets the PKCS10CertificationRequest. This object is NOT serializable.
     * 
     * @return PKCS10CertificationRequest
     */

    public PKCS10CertificationRequest getCertificateRequest() {

        return pKCS10Request;

    }

    /**
     * Reads the object from input stream and constructs PKCS10CertificationRequest.
     * 
     * @param inputStream
     *            The input stream object.
     * 
     * @throws IOException
     *             Throws in case of any io failures.
     * @throws ClassNotFoundException
     *             Throws in case of class not found.
     */
    private void readObject(final ObjectInputStream inputStream) throws IOException, ClassNotFoundException {

        inputStream.defaultReadObject();

        this.pKCS10Request = new PKCS10CertificationRequest(pkcs10Request);

    }

    /**
     * Writes the object to the stream.
     * 
     * @param outputStream
     *            The output stream object.
     * 
     * @throws IOException
     *             Throws in case of any io failures.
     */
    private void writeObject(final ObjectOutputStream outputStream) throws IOException {

        outputStream.defaultWriteObject();

    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(pkcs10Request);
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */
    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final PKCS10CertificationRequestHolder other = (PKCS10CertificationRequestHolder) obj;
        if (!Arrays.equals(pkcs10Request, other.pkcs10Request)) {
            return false;
        }
        return true;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "PKCS10CertificationRequestHolder [" + ((null == pkcs10Request) ? "" : ("pkcs10Request=" + Arrays.toString(pkcs10Request))) + "]";
    }

}
