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

import org.bouncycastle.cert.crmf.CertificateRequestMessage;

/**
 * Holder for CRMF request.
 * 
 * @author xprabil
 * 
 */
public class CRMFRequestHolder extends AbstractCertificateRequestHolder implements Serializable {

    private static final long serialVersionUID = -5195207296537485229L;

    private transient CertificateRequestMessage cRMFRequest;

    private final byte[] crmfRequest;

    /**
     * 
     * Constructs an CRMFRequestHolder object instance.
     * 
     * @param certificateRequestMessage
     *            The certificate request message object.
     * 
     * @throws IOException
     *             Throws in case of any io failures.
     * 
     */
    public CRMFRequestHolder(final CertificateRequestMessage certificateRequestMessage) throws IOException {

        this.cRMFRequest = certificateRequestMessage;

        this.crmfRequest = certificateRequestMessage.getEncoded();

    }

    /**
     * 
     * Gets the CertificateRequestMessage. This object is NOT serializable.
     * 
     * @return CertificateRequestMessage
     */
    public CertificateRequestMessage getCertificateRequest() {

        return cRMFRequest;

    }

    /**
     * Reads the object from input stream and constructs CertificateRequestMessage.
     * 
     * @param inputStream
     *            The input stream object.
     * 
     * @throws IOException
     *             Throws in case of any io failures.
     * @throws ClassNotFoundException
     *             Throws in case of class not found.
     */
    private void readObject(final ObjectInputStream ois) throws IOException, ClassNotFoundException {

        ois.defaultReadObject();

        this.cRMFRequest = new CertificateRequestMessage(crmfRequest);

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
    private void writeObject(final ObjectOutputStream oos) throws IOException {

        oos.defaultWriteObject();

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
        result = prime * result + Arrays.hashCode(crmfRequest);
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
        final CRMFRequestHolder other = (CRMFRequestHolder) obj;
        if (!Arrays.equals(crmfRequest, other.crmfRequest)) {
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
        return "CRMFRequestHolder [" + ((null == crmfRequest) ? "" : ("crmfRequest=" + Arrays.toString(crmfRequest))) + "]";
    }

}
