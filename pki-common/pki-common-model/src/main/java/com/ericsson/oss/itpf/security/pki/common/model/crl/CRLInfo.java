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
package com.ericsson.oss.itpf.security.pki.common.model.crl;

import java.io.Serializable;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;

/**
 * This Class contains all the attributes of a CRL as mentioned below.
 * 
 * <ul>
 * <li>CRLNumber: CRLNumber of the CRL.</li>
 * <li>thisUpdate : Time of the CRL generation.</li>
 * <li>nextUpdate : Expire Time of the CRL.</li>
 * <li>CRL : crl Instance.</li>
 * <li>Status : Status of the CRL whether it is active/expired.</li>
 * </ul>
 * This is used to represent the CRLInfo data of end entity/ CA entity.
 * 
 */
public class CRLInfo implements Serializable {

    private static final long serialVersionUID = -7638098697874808191L;

    private long id;

    private CRLNumber crlNumber;

    private Date thisUpdate;

    private Date nextUpdate;

    private Certificate issuerCertificate;

    private CRLStatus status;

    private CRL crl;

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
     * @return the crlNumber
     */
    public CRLNumber getCrlNumber() {
        return crlNumber;
    }

    /**
     * @param crlNumber
     *            the crlNumber to set
     */
    public void setCrlNumber(final CRLNumber crlNumber) {
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
     * @return the issuerCertificate
     */
    public Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    /**
     * @param issuerCertificate
     *            the issuerCertificate to set
     */
    public void setIssuerCertificate(final Certificate issuerCertificate) {
        this.issuerCertificate = issuerCertificate;
    }

    /**
     * @return the status
     */
    public CRLStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final CRLStatus status) {
        this.status = status;
    }

    /**
     * @return the crl
     */
    public CRL getCrl() {
        return crl;
    }

    /**
     * @param crl
     *            the crl to set
     */
    public void setCrl(final CRL crl) {
        this.crl = crl;
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((crlNumber == null) ? 0 : crlNumber.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((issuerCertificate == null) ? 0 : issuerCertificate.hashCode());
        result = prime * result + ((nextUpdate == null) ? 0 : nextUpdate.hashCode());
        result = prime * result + (publishedToCDPS ? 1231 : 1237);
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((thisUpdate == null) ? 0 : thisUpdate.hashCode());
        result = prime * result + ((crl == null) ? 0 : crl.hashCode());
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
        
        final CRLInfo other = (CRLInfo) obj;
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
        if (issuerCertificate == null) {
            if (other.issuerCertificate != null) {
                return false;
            }
        } else if (!issuerCertificate.equals(other.issuerCertificate)) {
            return false;
        }
        
        if (nextUpdate == null) {
            if (other.nextUpdate != null) {
                return false;
            }
        } else if (!nextUpdate.equals(other.nextUpdate)) {
            return false;
        }
        
        if (publishedToCDPS != other.publishedToCDPS) {
            return false;
        }
        
        if (status != other.status) {
            return false;
        }
        
        if (thisUpdate == null) {
            if (other.thisUpdate != null) {
                return false;
            }
        } else if (!thisUpdate.equals(other.thisUpdate)) {
            return false;
        }
        
        if (crl == null) {
            if (other.crl != null) {
                return false;
            }
        } else if (!crl.equals(other.crl)) {
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
        return "CRL [id=" + id + ", crlNumber=" + crlNumber + ", thisUpdate=" + thisUpdate + ", nextUpdate=" + nextUpdate + ", issuerCertificate=" + issuerCertificate + ", status=" + status
                + ", crl=" + crl + ", publishedToCDPS=" + publishedToCDPS + "]";
    }

}
