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
import java.util.Arrays;
import java.util.Date;

import javax.persistence.*;

/**
 * Represents ExternalCRLInfoData jpa entity to manage storage of CRLs
 */
@Entity
@Table(name = "ExternalCrlInfo")
public class ExternalCRLInfoData implements Serializable {

    /**
     *
     */
    private static final long serialVersionUID = 2330237990911157034L;

    @Id
    @Column(name = "id")
    @SequenceGenerator(name = "SEQ_EXT_CRL_ID_GENERATOR", sequenceName = "SEQ_EXT_CRL_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_EXT_CRL_ID_GENERATOR")
    private long id;

    @Column(name = "next_update", nullable = false)
    private Date nextUpdate;

    @Column(name = "auto_update", nullable = false)
    private boolean autoUpdate;

    @Column(name = "auto_update_check_timer")
    private Integer autoUpdateCheckTimer;

    @Column(name = "update_url")
    private String updateUrl;

    @Column(name = "crl", nullable = false)
    private byte[] crl;
    
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;
    
    /**
     * Sets current timestamp to createdDate and modifiedDate before
     * persist of ExternalCRLInfo in DB
     */
    @PrePersist
    protected void onCreate() {
        createdDate = new Date();
        modifiedDate = new Date();
    }

    /**
     * Sets current timestamp to modifiedDate before update of ExternalCRLInfo in DB
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
     * @param createdDate the createdDate to set
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
     * @param modifiedDate the modifiedDate to set
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
     * @return the autoUpdate
     */
    public boolean isAutoUpdate() {
        return autoUpdate;
    }

    /**
     * @param autoUpdate
     *            the autoUpdate to set
     */
    public void setAutoUpdate(final boolean autoUpdate) {
        this.autoUpdate = autoUpdate;
    }

    /**
     * @return the autoUpdateCheckTimer
     */
    public Integer getAutoUpdateCheckTimer() {
        return autoUpdateCheckTimer;
    }

    /**
     * @param autoUpdateCheckTimer
     *            the autoUpdateCheckTimer to set
     */
    public void setAutoUpdateCheckTimer(final Integer autoUpdateCheckTimer) {
        this.autoUpdateCheckTimer = autoUpdateCheckTimer;
    }

    /**
     * @return the updateUrl
     */
    public String getUpdateUrl() {
        return updateUrl;
    }

    /**
     * @param updateUrl
     *            the updateUrl to set
     */
    public void setUpdateUrl(final String updateUrl) {
        this.updateUrl = updateUrl;
    }

    /**
     * @return the crl
     */
    public byte[] getCrl() {
        return crl;
    }

    /**
     * @param crl
     *            the crl to set
     */
    public void setCrl(final byte[] crl) {
        this.crl = crl;
    }

    /**
     * @return the serialversionuid
     */
    public static long getSerialversionuid() {
        return serialVersionUID;
    }

    public String toSktring() {
        return "AlgorithmData [id=" + id + ", nextUpdate=" + nextUpdate + ", autoUpdate=" + autoUpdate + ", autoUpdateCheckTimer=" + autoUpdateCheckTimer + ", updateUrl=" + updateUrl + "]";
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
        result = prime * result + (autoUpdate ? 1231 : 1237);
        result = prime * result + ((autoUpdateCheckTimer == null) ? 0 : autoUpdateCheckTimer.hashCode());
        result = prime * result + Arrays.hashCode(crl);
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((nextUpdate == null) ? 0 : nextUpdate.hashCode());
        result = prime * result + ((updateUrl == null) ? 0 : updateUrl.hashCode());
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
        final ExternalCRLInfoData other = (ExternalCRLInfoData) obj;
        if (autoUpdate != other.autoUpdate) {
            return false;
        }
        if (autoUpdateCheckTimer == null) {
            if (other.autoUpdateCheckTimer != null) {
                return false;
            }
        } else if (!autoUpdateCheckTimer.equals(other.autoUpdateCheckTimer)) {
            return false;
        }
        if (!Arrays.equals(crl, other.crl)) {
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
        if (updateUrl == null) {
            if (other.updateUrl != null) {
                return false;
            }
        } else if (!updateUrl.equals(other.updateUrl)) {
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
        return "ExternalCRLInfoData [id=" + id + ", nextUpdate=" + nextUpdate + ", autoUpdate=" + autoUpdate + ", autoUpdateCheckTimer=" + autoUpdateCheckTimer + ", updateUrl=" + updateUrl + "]";
    }
}
