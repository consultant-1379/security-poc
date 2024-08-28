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
package com.ericsson.oss.itpf.security.pki.manager.model.crl;

import java.io.Serializable;
import java.util.Date;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;

/**
 * Class containing all the external attributes of the latest CRL like below.
 * 
 * <ul>
 * <li>Id : Identifier .</li>
 * <li>nextUpdate : Next update of the latest CRL.</li>
 * <li>autoUpdate : Automatic update of latest CRL enabled/disabled.</li>
 * <li>autoUpdateCheckTimer : Period of the automatic update check of latest CRL.</li>
 * <li>updateURL : The URL of the latest CRL used by the automatic update.</li>
 * <li>X509CRL : X509CRL Instance.</li>
 * </ul>
 * This is used to represent the External CRL information of CA.
 * 
 */
@XmlRootElement(name = "ExternalCRLInfo")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ExternalCRLInfo", propOrder = { "id", "nextUpdate", "autoUpdate", "autoUpdateCheckTimer", "updateURL" })
public class ExternalCRLInfo implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -2905965255308007867L;

    @XmlAttribute(name = "Id")
    protected long id;

    @XmlElement(name = "NextUpdate")
    protected Date nextUpdate;

    @XmlElement(name = "AutoUpdate")
    protected Boolean autoUpdate;

    @XmlElement(name = "AutoUpdateCheckTimer")
    protected Integer autoUpdateCheckTimer;

    @XmlTransient
    protected X509CRLHolder x509CRL;

    @XmlElement(name = "UpdateURL")
    protected String updateURL;

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
    public Boolean isAutoUpdate() {
        return autoUpdate;
    }

    /**
     * @param autoUpdate
     *            the autoUpdate to set
     */
    public void setAutoUpdate(final Boolean autoUpdate) {
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
     * @return the updateURL
     */
    public String getUpdateURL() {
        return updateURL;
    }

    /**
     * @param updateURL
     *            the updateURL to set
     */
    public void setUpdateURL(final String updateURL) {
        this.updateURL = updateURL;
    }

    /**
     * @return the x509CRL
     */
    public X509CRLHolder getX509CRL() {
        return x509CRL;
    }

    /**
     * @param x509CRL
     *            the x509CRL to set
     */
    public void setX509CRL(final X509CRLHolder x509CRL) {
        this.x509CRL = x509CRL;
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
        result = prime * result + ((nextUpdate == null) ? 0 : nextUpdate.hashCode());
        result = prime * result + ((autoUpdate == null) ? 0 : autoUpdate.hashCode());
        result = prime * result + ((autoUpdateCheckTimer == null) ? 0 : autoUpdateCheckTimer.hashCode());
        result = prime * result + ((updateURL == null) ? 0 : updateURL.hashCode());
        result = prime * result + ((x509CRL == null) ? 0 : x509CRL.hashCode());
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
        final ExternalCRLInfo other = (ExternalCRLInfo) obj;
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
        if (autoUpdate == null) {
            if (other.autoUpdate != null) {
                return false;
            }
        } else if (!autoUpdate.equals(other.autoUpdate)) {
            return false;
        }
        if (autoUpdateCheckTimer == null) {
            if (other.autoUpdateCheckTimer != null) {
                return false;
            }
        } else if (!autoUpdateCheckTimer.equals(other.autoUpdateCheckTimer)) {
            return false;
        }
        if (updateURL == null) {
            if (other.updateURL != null) {
                return false;
            }
        } else if (!updateURL.equals(other.updateURL)) {
            return false;
        }
        if (x509CRL == null) {
            if (other.x509CRL != null) {
                return false;
            }
        } else if (!x509CRL.equals(other.x509CRL)) {
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
        return "Certificate [id=" + id + ", " + (null != nextUpdate ? "nextUpdate=" + nextUpdate + ", " : "") + (null != autoUpdate ? "autoUpdate=" + autoUpdate + ", " : "")
                + (null != autoUpdateCheckTimer ? "autoUpdateCheckTimer=" + autoUpdateCheckTimer + ", " : "") + (null != updateURL ? "updateURL=" + updateURL + ", " : "")
                + (null != x509CRL ? "x509CRL=" + x509CRL + ", " : "") + "]";
    }

}
