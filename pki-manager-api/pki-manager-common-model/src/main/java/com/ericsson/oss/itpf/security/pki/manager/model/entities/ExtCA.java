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
package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import java.io.Serializable;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.XmlType;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

/**
 * <p>
 * This class manages external certificate authority.
 *
 * <p>
 * This class cannot be used for bulk import via xml.
 */
@XmlRootElement(name = "ExtCA")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ExtCA", propOrder = { "certificateAuthority" })
public class ExtCA implements Serializable {

    private static final long serialVersionUID = 26334851108885359L;

    @XmlElement(name = "CertificateAuthority")
    protected CertificateAuthority certificateAuthority;

    @XmlTransient
    private List<ExtCA> associated;

    @XmlTransient
    protected ExternalCRLInfo externalCRLInfo;

    /**
     * @return the certificateAuthority
     */
    public CertificateAuthority getCertificateAuthority() {
        return certificateAuthority;
    }

    /**
     * @param certificateAuthority
     *            the certificateAuthority to set
     */
    public void setCertificateAuthority(final CertificateAuthority certificateAuthority) {
        this.certificateAuthority = certificateAuthority;
    }

    /**
     * @return the externalCRLInfo
     */
    public ExternalCRLInfo getExternalCRLInfo() {
        return externalCRLInfo;
    }

    /**
     * @param externalCRLInfo
     *            the externalCRLInfo to set
     */
    public void setExternalCRLInfo(final ExternalCRLInfo externalCRLInfo) {
        this.externalCRLInfo = externalCRLInfo;
    }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "ExtCA [" + super.toString() + ", " + (null != certificateAuthority ? "certificateAuthority=" + certificateAuthority : "") + "]";
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
        result = prime * result + ((associated == null) ? 0 : associated.hashCode());
        result = prime * result + ((certificateAuthority == null) ? 0 : certificateAuthority.hashCode());
        result = prime * result + ((externalCRLInfo == null) ? 0 : externalCRLInfo.hashCode());
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
        final ExtCA other = (ExtCA) obj;
        if (associated == null) {
            if (other.associated != null) {
                return false;
            }
        } else if (!associated.equals(other.associated)) {
            return false;
        }
        if (certificateAuthority == null) {
            if (other.certificateAuthority != null) {
                return false;
            }
        } else if (!certificateAuthority.equals(other.certificateAuthority)) {
            return false;
        }
        if (externalCRLInfo == null) {
            if (other.externalCRLInfo != null) {
                return false;
            }
        } else if (!externalCRLInfo.equals(other.externalCRLInfo)) {
            return false;
        }
        return true;
    }

    /**
     * @return the associated
     */
    public List<ExtCA> getAssociated() {
        return associated;
    }

    /**
     * @param associated
     *            the associated to set
     */
    public void setAssociated(final List<ExtCA> associated) {
        this.associated = associated;
    }

}