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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.io.Serializable;
import java.util.Date;

import javax.persistence.*;

@Entity
@Table(name = "crlinfo")
public class CRLInfoData implements Serializable {

    private static final long serialVersionUID = -5406398813257803844L;

    @Id
    @SequenceGenerator(name = "SEQ_CRLINFO_ID_GENERATOR", sequenceName = "SEQ_CRLINFO_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CRLINFO_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "crl_number", nullable = false)
    private Integer crlNumber;

    @Column(name = "this_update", nullable = false)
    private Date thisUpdate;

    @Column(name = "next_update", nullable = false)
    private Date nextUpdate;

    @OneToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE, CascadeType.REMOVE })
    @JoinColumn(name = "crl_id", nullable = false)
    private CRLData crl;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "certificate_id", nullable = true)
    private CertificateData issuerCertificateData;

    @Column(name = "published_to_cdps")
    private boolean publishedToCdps;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;

    /**
     * Sets current timestamp to createdDate and modifiedDate before persist of CRLInfo
     */
    @PrePersist
    protected void onCreate() {
        createdDate = new Date();
        modifiedDate = new Date();
    }

    /**
     * Sets current timestamp to modifiedDate before update of CRLInfo
     */
    @PreUpdate
    protected void onUpdate() {
        modifiedDate = new Date();
    }

    /**
     * @return the createdDate
     */
    public Date getCreatedDate() {
        return createdDate;
    }

    /**
     * @param createdDate
     *            the createdDate to set
     */
    public void setCreatedDate(final Date createdDate) {
        this.createdDate = createdDate;
    }

    /**
     * @return the modifiedDate
     */
    public Date getModifiedDate() {
        return modifiedDate;
    }

    /**
     * @param modifiedDate
     *            the modifiedDate to set
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

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
     * @return the crlnumber
     */
    public Integer getCrlnumber() {
        return crlNumber;
    }

    /**
     * @param crlnumber
     *            the crlnumber to set
     */
    public void setCrlnumber(final Integer crlnumber) {
        this.crlNumber = crlnumber;
    }

    /**
     * @return the thisUpdate
     */
    public Date getThisUpdate() {
        return thisUpdate;
    }

    /**
     * @param thisUpdate
     *            the thisUpdate to set
     */
    public void setThisUpdate(final Date thisUpdate) {
        this.thisUpdate = thisUpdate;
    }

    /**
     * @return the nextUpdate
     */
    public Date getNextUpdate() {
        return nextUpdate;
    }

    /**
     * @param nextUpdate
     *            the nextUpdate to set
     */
    public void setNextUpdate(final Date nextUpdate) {
        this.nextUpdate = nextUpdate;
    }

    /**
     * @return the crl
     */
    public CRLData getCrl() {
        return crl;
    }

    /**
     * @param crl
     *            the crl to set
     */
    public void setCrl(final CRLData crl) {
        this.crl = crl;
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
     * @return the certificateData
     */
    public CertificateData getCertificateData() {
        return issuerCertificateData;
    }

    /**
     * @param certificateData
     *            the certificateData to set
     */
    public void setCertificateData(final CertificateData certificateData) {
        this.issuerCertificateData = certificateData;
    }

    /**
     * @return the publishTocdps
     */
    public boolean isPublishedTocdps() {
        return publishedToCdps;
    }

    /**
     * @param publishTocdps
     *            the publishTocdps to set
     */
    public void setPublishedTocdps(final boolean publishTocdps) {
        this.publishedToCdps = publishTocdps;
    }

    @Override
    public String toString() {
        return "CRLData [id=" + id + ", crlnumber=" + crlNumber + ", thisUpdate=" + thisUpdate + ", nextUpdate=" + nextUpdate + ", crl=" + crl + ", status=" + status + ", publishTocdps="
                + publishedToCdps + ", certificateData=" + issuerCertificateData + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((issuerCertificateData == null) ? 0 : issuerCertificateData.hashCode());
        result = prime * result + ((crl == null) ? 0 : crl.hashCode());
        result = prime * result + ((crlNumber == null) ? 0 : crlNumber.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((nextUpdate == null) ? 0 : nextUpdate.hashCode());
        result = prime * result + (publishedToCdps ? 1231 : 1237);
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((thisUpdate == null) ? 0 : thisUpdate.hashCode());
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

        final CRLInfoData other = (CRLInfoData) obj;
        if (issuerCertificateData == null) {
            if (other.issuerCertificateData != null) {
                return false;
            }
        } else if (!issuerCertificateData.equals(other.issuerCertificateData)) {
            return false;
        }

        if (crl == null) {
            if (other.crl != null) {
                return false;
            }
        } else if (!crl.equals(other.crl)) {
            return false;
        }

        if (crlNumber == null) {
            if (other.crlNumber != null) {
                return false;
            }
        } else if (!crlNumber.equals(other.crlNumber)) {
            return false;
        }

        if (id != other.id) {
            return false;
        }

        if (nextUpdate == null) {
            if (other.nextUpdate != null) {
                return false;
            }
        } else if (!nextUpdate.equals(other.nextUpdate)) {
            return false;
        }

        if (publishedToCdps != other.publishedToCdps) {
            return false;
        }

        if (status == null) {
            if (other.status != null) {
                return false;
            }
        } else if (!status.equals(other.status)) {
            return false;
        }

        if (thisUpdate == null) {
            if (other.thisUpdate != null) {
                return false;
            }
        } else if (!thisUpdate.equals(other.thisUpdate)) {
            return false;
        }

        return true;
    }
}
