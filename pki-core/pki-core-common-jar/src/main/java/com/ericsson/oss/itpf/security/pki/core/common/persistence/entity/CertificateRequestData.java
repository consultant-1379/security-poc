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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.entity;

import java.io.Serializable;
import java.util.Arrays;

import javax.persistence.*;

/**
 * Represents CSR generated for Entity and CAEntity.
 * 
 */
@Entity
@Table(name = "certificate_request")
public class CertificateRequestData implements Serializable {

    private static final long serialVersionUID = -5509726099806005428L;

    @Id
    @SequenceGenerator(name = "SEQ_CERTIFICATE_REQUEST_ID_GENERATOR", sequenceName = "SEQ_CERTIFICATE_REQUEST_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CERTIFICATE_REQUEST_ID_GENERATOR")
    private long id;

    @Column(name = "certificate_request", nullable = false)
    byte[] certificateRequest;

    @Column(name = "status_id", nullable = false)
    private Integer status;

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
     * @return the certificateRequest
     */
    public byte[] getCsr() {
        return certificateRequest;
    }

    /**
     * @param csr
     *            the csr to set
     */
    public void setCsr(final byte[] certificateRequest) {
        this.certificateRequest = certificateRequest;
    }

    /**
     * @return the status
     */
    public Integer getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final Integer status) {
        this.status = status;
    }

    /**
     * Returns the has code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Arrays.hashCode(certificateRequest);
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        return result;
    }

    /**
     * Indicates whether the invoking object is "equal to" the parameterized object
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
        final CertificateRequestData other = (CertificateRequestData) obj;
        if (!Arrays.equals(this.getCsr(), other.getCsr())) {
            return false;
        }
        if (this.getId() != other.getId()) {
            return false;
        }
        if (this.getStatus() == null) {
            if (other.getStatus() != null) {
                return false;
            }
        } else if (!this.getStatus().equals(other.getStatus())) {
            return false;
        }

        return true;
    }

    /**
     * Returns string representation of {@link CertificateRequestData} object.
     */
    @Override
    public String toString() {
        return "CertificateRequestData [id=" + id + ", csr=" + Arrays.toString(certificateRequest) + ", status=" + status + "]";
    }
}
