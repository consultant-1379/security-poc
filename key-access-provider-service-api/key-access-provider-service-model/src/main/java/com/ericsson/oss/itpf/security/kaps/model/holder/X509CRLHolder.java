/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.kaps.model.holder;

import java.io.Serializable;
import java.security.cert.X509CRL;
import java.util.Arrays;

/**
 * This class holds {@link X509CRL} bytes.
 *
 */
public class X509CRLHolder implements Serializable {

    private static final long serialVersionUID = 817575636689206781L;

    private byte[] crlBytes;

    /**
     * @return the crlBytes
     */
    public byte[] getCrlBytes() {
        return crlBytes;
    }

    /**
     * @param crlBytes
     *            the crlBytes to set
     */
    public void setCrlBytes(final byte[] crlBytes) {
        this.crlBytes = crlBytes;
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
        result = prime * result + (crlBytes == null ? 0 : Arrays.hashCode(crlBytes));
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
        final X509CRLHolder other = (X509CRLHolder) obj;

        if (crlBytes == null) {
            if (other.crlBytes != null) {
                return false;
            }
        } else if (!(Arrays.equals(crlBytes, other.crlBytes))) {
            return false;
        }
        return true;
    }

}
