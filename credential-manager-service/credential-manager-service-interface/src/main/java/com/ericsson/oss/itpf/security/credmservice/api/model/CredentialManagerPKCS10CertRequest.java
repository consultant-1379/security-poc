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
import java.security.cert.CertificateException;
import java.util.Arrays;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;



/**
 * This class was created because PKCS10CertificationRequest is not serializable properly.
 */

public class CredentialManagerPKCS10CertRequest implements Serializable {

    private static final long serialVersionUID = -5195207296537485229L;

    private transient PKCS10CertificationRequest wrapped;
    private final byte[] requestBytes;

    /**
     * Constructs an CredentialManagerPKCS10CertRequest object instance
     *
     * @param request
     * @throws CertificateEncodingException
     *             in case the input can not be encoded.
     * @throws IOException 
     */
    public CredentialManagerPKCS10CertRequest(final PKCS10CertificationRequest request) throws IOException {
        this.wrapped = request;
			this.requestBytes = request.getEncoded();
    }

    /**
     * Gets the certRequest in PKCS10 format
     *
     * @return certRequest
     */
    public PKCS10CertificationRequest getRequest() {
        return wrapped;
    }

    private void readObject(final ObjectInputStream ois) throws IOException, ClassNotFoundException, CertificateException {
        ois.defaultReadObject();
        this.wrapped = new PKCS10CertificationRequest(requestBytes);
    }

    private void writeObject(final ObjectOutputStream oos) throws IOException {
        oos.defaultWriteObject();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(requestBytes);
        return result;
    }

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
        final CredentialManagerPKCS10CertRequest other = (CredentialManagerPKCS10CertRequest) obj;
        if (!Arrays.equals(requestBytes, other.requestBytes)) {
            return false;
        }
        return true;
    }
}
