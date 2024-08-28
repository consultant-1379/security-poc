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

import java.io.Serializable;

/**
 * This class holds PKCS10 Certificate Request holder or CRMFRequest Holder with request status and Certificate that is generated using this CSR.
 * 
 */
public class CertificateRequest implements Serializable {

    private static final long serialVersionUID = 6732429338055448138L;
    protected long id;
    protected AbstractCertificateRequestHolder certificateRequestHolder;
    protected CertificateRequestStatus status;

    /**
     * @return the id
     */
    public long getId() {
        return id;
    }

    /**
     * @param id
     *            the id to set
     */
    public void setId(final long id) {
        this.id = id;
    }

    /**
     * @return the status
     */
    public CertificateRequestStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final CertificateRequestStatus status) {
        this.status = status;
    }

    /**
     * @return the certificateRequestHolder
     */
    public AbstractCertificateRequestHolder getCertificateRequestHolder() {
        return certificateRequestHolder;
    }

    /**
     * @param certificateRequestHolder
     *            the certificateRequestHolder to set
     */
    public void setCertificateRequestHolder(final AbstractCertificateRequestHolder certificateRequestHolder) {
        this.certificateRequestHolder = certificateRequestHolder;
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
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((certificateRequestHolder == null) ? 0 : certificateRequestHolder.hashCode());
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
        final CertificateRequest other = (CertificateRequest) obj;
        if (certificateRequestHolder == null) {
            if (other.certificateRequestHolder != null) {
                return false;
            }
        } else if (!certificateRequestHolder.equals(other.certificateRequestHolder)) {
            return false;
        }
        if (status != other.status) {
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
        return "CertificateRequest [id=" + id + ", " + (null != certificateRequestHolder ? "certificateRequestHolder=" + certificateRequestHolder + ", " : "")
                + (null != status ? "requestStatus=" + status : "") + "]";
    }

}
