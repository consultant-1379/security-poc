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
import java.util.Date;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;

@Entity
@Table(name = "crlinfo")
public class CRLInfoData implements Serializable {

    private static final long serialVersionUID = 8666362305003144721L;

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

    @OneToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE })
    @JoinColumn(name = "crl_id", nullable = false)
    private CRLData crl;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "certificate_id", nullable = true)
    private CertificateData certificateData;

    @Column(name = "published_to_cdps", nullable = false)
    private boolean publishedToCDPS;

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
    public Integer getCrlNumber() {
        return crlNumber;
    }

    /**
     * @param crlnumber
     *            the crlnumber to set
     */
    public void setCrlNumber(final Integer crlNumber) {
        this.crlNumber = crlNumber;
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
     * @return the Entity Status
     */
    public CRLStatus getStatus() {
        return CRLStatus.getStatus(this.status);
    }

    /**
     * @param entityStatus
     *            entity status to be set.
     */
    public void setStatus(final CRLStatus cRLStatus) {

        if (cRLStatus == null) {
            this.status = null;
        } else {
            this.status = cRLStatus.getId();
        }
    }

    /**
     * @return the certificateData
     */
    public CertificateData getCertificateData() {
        return certificateData;
    }

    /**
     * @param certificateData
     *            the certificateData to set
     */
    public void setCertificateData(final CertificateData certificateData) {
        this.certificateData = certificateData;
    }

    /**
     * @return the publishedToCDPS
     */
    public boolean isPublishedToCDPS() {
        return publishedToCDPS;
    }

    /**
     * @param publishedToCDPS
     *            the publishedToCDPS to set
     */
    public void setPublishedToCDPS(final boolean publishedToCDPS) {
        this.publishedToCDPS = publishedToCDPS;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certificateData == null) ? 0 : certificateData.hashCode());
        result = prime * result + ((crl == null) ? 0 : crl.hashCode());
        result = prime * result + ((crlNumber == null) ? 0 : crlNumber.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((nextUpdate == null) ? 0 : nextUpdate.hashCode());
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
        if (certificateData == null) {
            if (other.certificateData != null) {
                return false;
            }
        } else if (!certificateData.equals(other.certificateData)) {
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

    @Override
    public String toString() {
        return "CRLData [id=" + id + ", crlnumber=" + crlNumber + ", thisUpdate=" + thisUpdate + ", nextUpdate=" + nextUpdate + ", crl=" + crl + ", status=" + status + ", certificateData="
                + certificateData + "]";
    }
}