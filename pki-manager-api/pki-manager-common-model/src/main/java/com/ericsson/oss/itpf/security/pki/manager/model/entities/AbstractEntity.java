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
import java.util.HashSet;
import java.util.Set;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

/**
 * <p>
 * This is a super class of CAEntity and Entity containing common properties shared between CAEntity and Entity.
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * <pre>
 * &lt;complexType name="AbstractEntity">
 * &lt;complexContent>
 * &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 * &lt;sequence>
 * &lt;element name="EntityProfile" type="EntityProfile"/>
 * &lt;element name="PublishCertificatetoTDPS" type="xs:boolean" minOccurs="0" />
 * &lt;element name="SubjectUniqueIdentifierValue" type="xs:String" minOccurs="0" />
 * &lt;element name="CertificateExpiryNotificationDetails" type="CertificateExpiryNotificationDetails" minOccurs="0" maxOccurs="4"/>
 * &lt;/sequence>
 * &lt;/restriction>
 * &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AbstractEntity", propOrder = { "publishCertificatetoTDPS", "entityProfile", "subjectUniqueIdentifierValue",
    "certificateExpiryNotificationDetails" })
@XmlSeeAlso({ Entity.class, CAEntity.class })
public abstract class AbstractEntity implements Serializable {
    /**
	 *
	 */
    private static final long serialVersionUID = -8852377180841518342L;

    @XmlTransient
    protected EntityType type;
    @XmlElement(name = "PublishCertificatetoTDPS")
    protected boolean publishCertificatetoTDPS;
    @XmlElement(name = "EntityProfile")
    protected EntityProfile entityProfile;
    @XmlElement(name = "SubjectUniqueIdentifierValue")
    protected String subjectUniqueIdentifierValue;
    @XmlElement(name = "CertificateExpiryNotificationDetails", required = false)
    protected Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetails>();

    /**
     * @return the entityType
     */
    public EntityType getType() {
        return type;
    }

    /**
     * @param entityType
     *            the entityType to set
     */
    public void setType(final EntityType type) {
        this.type = type;
    }

    /**
     * @return the publishCertificatetoTDPS
     */
    public boolean isPublishCertificatetoTDPS() {
        return publishCertificatetoTDPS;
    }

    /**
     * @param publishCertificatetoTDPS
     *            the publishCertificatetoTDPS to set
     */
    public void setPublishCertificatetoTDPS(final boolean publishCertificatetoTDPS) {
        this.publishCertificatetoTDPS = publishCertificatetoTDPS;
    }

    /**
     * @return the entityProfile
     */
    public EntityProfile getEntityProfile() {
        return entityProfile;
    }

    /**
     * @param entityProfile
     *            the entityProfile to set
     */
    public void setEntityProfile(final EntityProfile entityProfile) {
        this.entityProfile = entityProfile;
    }

    /**
     * @return the subjectUniqueIdentifierValue
     */
    public String getSubjectUniqueIdentifierValue() {
        return subjectUniqueIdentifierValue;
    }

    /**
     * @param subjectUniqueIdentifierValue
     *            the subjectUniqueIdentifierValue to set
     */
    public void setSubjectUniqueIdentifierValue(final String subjectUniqueIdentifierValue) {
        this.subjectUniqueIdentifierValue = subjectUniqueIdentifierValue;
    }

    /**
     * @return the certificateExpiryNotificationDetails
     */
    public Set<CertificateExpiryNotificationDetails> getCertificateExpiryNotificationDetails() {
        return certificateExpiryNotificationDetails;
    }

    /**
     * @param certificateExpiryNotificationDetails
     *            the certificateExpiryNotificationDetails to set
     */
    public void setCertificateExpiryNotificationDetails(final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails) {
        this.certificateExpiryNotificationDetails = certificateExpiryNotificationDetails;
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return (null != type ? "type=" + type + ", " : "")
                + "publishCertificatetoTDPS="
                + publishCertificatetoTDPS
                + ", "
                + (null != entityProfile ? "entityProfile=" + entityProfile : "")
                + (null != subjectUniqueIdentifierValue ? "subjectUniqueIdentifierValue=" + subjectUniqueIdentifierValue + ", " : "")
                + (null != certificateExpiryNotificationDetails ? "certificateExpiryNotificationDetails=" + certificateExpiryNotificationDetails : "");
    }

    /*
     * (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (entityProfile == null ? 0 : entityProfile.hashCode());
        result = prime * result + (publishCertificatetoTDPS ? 1231 : 1237);
        result = prime * result + (type == null ? 0 : type.hashCode());
        result = prime * result + (subjectUniqueIdentifierValue == null ? 0 : subjectUniqueIdentifierValue.hashCode());
        result = prime * result + (certificateExpiryNotificationDetails == null ? 0 : certificateExpiryNotificationDetails.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
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
        final AbstractEntity other = (AbstractEntity) obj;

        if (entityProfile == null) {
            if (other.entityProfile != null) {
                return false;
            }
        } else if (!entityProfile.equals(other.entityProfile)) {
            return false;
        }
        if (publishCertificatetoTDPS != other.publishCertificatetoTDPS) {
            return false;
        }
        if (type != other.type) {
            return false;
        }
        if (subjectUniqueIdentifierValue == null) {
            if (other.subjectUniqueIdentifierValue != null) {
                return false;
            }
        } else if (!subjectUniqueIdentifierValue.equals(other.subjectUniqueIdentifierValue)) {
            return false;
        }

        if (certificateExpiryNotificationDetails != null && other.certificateExpiryNotificationDetails != null) {
            boolean isMatched = false;
            for (final CertificateExpiryNotificationDetails certificateExpiryNotificationDetail : certificateExpiryNotificationDetails) {
                for (final CertificateExpiryNotificationDetails certificateExpiryNotificationDetailsOther : other.certificateExpiryNotificationDetails) {
                    if (certificateExpiryNotificationDetail.equals(certificateExpiryNotificationDetailsOther)) {
                        isMatched = true;
                        break;
                    }
                }
                if (!isMatched) {
                    return false;
                }
                isMatched = false;
            }
        } else if (certificateExpiryNotificationDetails == null) {
            if (other.certificateExpiryNotificationDetails != null) {
                return false;
            }
        } else if (other.certificateExpiryNotificationDetails == null) {
            return false;
        }

        return true;
    }

}
