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

package com.ericsson.oss.itpf.security.pki.manager.model.profiles;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

/**
 * <p>
 * This class holds all trustprofiles,entity profiles and certificate profiles.This is the root element in xml.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="Profiles">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *       &lt;element name="TrustProfile" type="TrustProfile" minOccurs="0" maxOccurs="unbounded" />
 *       &lt;element name="CertificateProfile" type="CertificateProfile" minOccurs="0" maxOccurs="unbounded" />
 *       &lt;element name="EntityProfile" type="EntityProfile" minOccurs="0" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "Profiles")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Profiles", propOrder = { "trustProfiles", "certificateProfiles", "entityProfiles" })
public class Profiles implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = 2510322375384938307L;
    @XmlElement(name = "TrustProfile", required = false)
    protected List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();
    @XmlElement(name = "CertificateProfile", required = false)
    protected List<CertificateProfile> certificateProfiles = new ArrayList<CertificateProfile>();
    @XmlElement(name = "EntityProfile", required = false)
    protected List<EntityProfile> entityProfiles = new ArrayList<EntityProfile>();

    /**
     * @return the trustProfiles
     */
    public List<TrustProfile> getTrustProfiles() {
        return trustProfiles;
    }

    /**
     * @param trustProfiles
     *            the trustProfiles to set
     */
    public void setTrustProfiles(final List<TrustProfile> trustProfiles) {
        this.trustProfiles = trustProfiles;
    }

    /**
     * @return the certificateProfiles
     */
    public List<CertificateProfile> getCertificateProfiles() {
        return certificateProfiles;
    }

    /**
     * @param certificateProfiles
     *            the certificateProfiles to set
     */
    public void setCertificateProfiles(final List<CertificateProfile> certificateProfiles) {
        this.certificateProfiles = certificateProfiles;
    }

    /**
     * @return the entityProfiles
     */
    public List<EntityProfile> getEntityProfiles() {
        return entityProfiles;
    }

    /**
     * @param entityProfiles
     *            the entityProfiles to set
     */
    public void setEntityProfiles(final List<EntityProfile> entityProfiles) {
        this.entityProfiles = entityProfiles;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "Profiles [" + (null != trustProfiles ? "trustProfiles=" + trustProfiles + ", " : "") + (null != certificateProfiles ? "certificateProfiles=" + certificateProfiles + ", " : "")
                + (null != entityProfiles ? "entityProfiles=" + entityProfiles : "") + "]";
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
        result = prime * result + ((certificateProfiles == null) ? 0 : certificateProfiles.hashCode());
        result = prime * result + ((entityProfiles == null) ? 0 : entityProfiles.hashCode());
        result = prime * result + ((trustProfiles == null) ? 0 : trustProfiles.hashCode());
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
        final Profiles other = (Profiles) obj;
        if (certificateProfiles == null) {
            if (other.certificateProfiles != null) {
                return false;
            }
        } else if (certificateProfiles.size() != other.certificateProfiles.size()) {
            return false;
        } else if (certificateProfiles != null && other.certificateProfiles != null) {
            boolean isMatched = false;
            for (final CertificateProfile certificateProfile : certificateProfiles) {
                for (final CertificateProfile certificateProfileOther : other.certificateProfiles) {
                    if (certificateProfile.equals(certificateProfileOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        if (entityProfiles == null) {
            if (other.entityProfiles != null) {
                return false;
            }
        } else if (entityProfiles.size() != other.entityProfiles.size()) {
            return false;
        } else if (entityProfiles != null && other.entityProfiles != null) {
            boolean isMatched = false;
            for (final EntityProfile entityProfile : entityProfiles) {
                for (final EntityProfile entityProfileOther : other.entityProfiles) {
                    if (entityProfile.equals(entityProfileOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        if (trustProfiles == null) {
            if (other.trustProfiles != null) {
                return false;
            }
        } else if (trustProfiles.size() != other.trustProfiles.size()) {
            return false;
        } else if (trustProfiles != null && other.trustProfiles != null) {
            boolean isMatched = false;
            for (final TrustProfile trustProfile : trustProfiles) {
                for (final TrustProfile trustProfileOther : other.trustProfiles) {
                    if (trustProfile.equals(trustProfileOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        }
        return true;
    }
}
