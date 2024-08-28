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

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;

/**
 * <p>
 * As certificate profiles create separate configuration for CAs, there is a need to define templates for entities, as many entities could have very similar certificates. For example, all AIWeb
 * application has almost the similar DN, or all nodes could have similar DN.
 * 
 * The entity profile makes it possible to create a template for a set of entities, and the PKI can use this to issue the certificate for those entities, by substituting the variable content of the
 * profile.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="EntityProfile">
 *   &lt;complexContent>
 *     &lt;extension base="{}AbstractProfile">
 *       &lt;sequence>
 *         &lt;element name="Subject" type="{}Subject"/>
 *         &lt;element name="Category" type="{}EntityCategory"/>
 *         &lt;element name="SubjectAltName" type="SubjectAltName" minOccurs="0" />
 *         &lt;element name="ExtendedKeyUsage" type="{}ExtendedKeyUsage" minOccurs="0"/>
 *         &lt;element name="KeyUsage" type="{}KeyUsage" minOccurs="0"/>
 *         &lt;element name="KeyGenerationAlgorithm" type="{}Algorithm"/>
 *         &lt;element name="CertificateProfile" type="{}CertificateProfile" minOccurs="1"/>
 *         &lt;element name="TrustProfile" type="{}TrustProfile" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element name="SubjectUniqueIdentifierValue" type="xs:string" minOccurs="0" />
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "EntityProfile")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EntityProfile", propOrder = { "category", "subject", "subjectAltNameExtension", "keyGenerationAlgorithm", "certificateProfile",
        "trustProfiles", "keyUsageExtension", "extendedKeyUsageExtension", "subjectUniqueIdentifierValue" })
public class EntityProfile extends AbstractProfile implements Serializable {

    /**
         * 
         */
    private static final long serialVersionUID = 8326261319369167297L;

    @XmlElement(name = "Subject", required = true)
    protected Subject subject;

    @XmlElement(name = "Category", required = true)
    protected EntityCategory category;

    @XmlElement(name = "SubjectAltName", required = false)
    protected SubjectAltName subjectAltNameExtension;

    @XmlElement(name = "ExtendedKeyUsage", required = false)
    protected ExtendedKeyUsage extendedKeyUsageExtension;

    @XmlElement(name = "KeyUsage", required = false)
    protected KeyUsage keyUsageExtension;

    @XmlElement(name = "KeyGenerationAlgorithm", required = false)
    protected Algorithm keyGenerationAlgorithm;

    @XmlElement(name = "CertificateProfile", required = true)
    protected CertificateProfile certificateProfile;

    @XmlElement(name = "TrustProfile", required = false)
    protected List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

    @XmlElement(name = "SubjectUniqueIdentifierValue", required = false)
    protected String subjectUniqueIdentifierValue;

    public EntityProfile() {
        setType(ProfileType.ENTITY_PROFILE);
    }

    /**
     * @return the keyGenerationAlgorithm
     */
    public Algorithm getKeyGenerationAlgorithm() {
        return keyGenerationAlgorithm;
    }

    /**
     * @param keyGenerationAlgorithm
     *            the keyGenerationAlgorithm to set
     */
    public void setKeyGenerationAlgorithm(final Algorithm keyGenerationAlgorithm) {
        this.keyGenerationAlgorithm = keyGenerationAlgorithm;
    }

    /**
     * Gets the value of the subject property.
     * 
     * @return possible object is {@link Subject }
     * 
     */
    public Subject getSubject() {
        return subject;
    }

    /**
     * Sets the value of the subject property.
     * 
     * @param value
     *            allowed object is {@link Subject }
     * 
     */
    public void setSubject(final Subject value) {
        this.subject = value;
    }

    /**
     * @return the subjectAltName
     */
    public SubjectAltName getSubjectAltNameExtension() {
        return subjectAltNameExtension;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltNameExtension(final SubjectAltName subjectAltNameExtension) {
        this.subjectAltNameExtension = subjectAltNameExtension;
    }

    /**
     * @return the entityCategory
     */
    public EntityCategory getCategory() {
        return category;
    }

    /**
     * @param entityCategory
     *            the entityCategory to set
     */
    public void setCategory(final EntityCategory entityCategory) {
        this.category = entityCategory;
    }

    /**
     * @return the extendedKeyUsageExtension
     */
    public ExtendedKeyUsage getExtendedKeyUsageExtension() {
        return extendedKeyUsageExtension;
    }

    /**
     * @param extendedKeyUsageExtension
     *            the extendedKeyUsageExtension to set
     */
    public void setExtendedKeyUsageExtension(final ExtendedKeyUsage extendedKeyUsageExtension) {
        this.extendedKeyUsageExtension = extendedKeyUsageExtension;
    }

    /**
     * @return the keyUsageExtension
     */
    public KeyUsage getKeyUsageExtension() {
        return keyUsageExtension;
    }

    /**
     * @param keyUsageExtension
     *            the keyUsageExtension to set
     */
    public void setKeyUsageExtension(final KeyUsage keyUsageExtension) {
        this.keyUsageExtension = keyUsageExtension;
    }

    /**
     * @return the active
     */
    public boolean isActive() {
        return active;
    }

    /**
     * @param active
     *            the active to set
     */
    public void setActive(final boolean active) {
        this.active = active;
    }

    /**
     * @return the certificateProfile
     */
    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }

    /**
     * @param certificateProfile
     *            the certificateProfile to set
     */
    public void setCertificateProfile(final CertificateProfile certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "EntityProfile [" + super.toString() + ", " + (null != subject ? "subject=" + subject + ", " : "")
                + (null != subjectAltNameExtension ? "subjectAltNameValues=" + subjectAltNameExtension + ", " : "")
                + (null != keyGenerationAlgorithm ? "keyGenerationAlgorithm=" + keyGenerationAlgorithm + ", " : "") + (null != category ? "entityCategory=" + category + ", " : "")
                + (null != extendedKeyUsageExtension ? "extendedKeyUsageExtension=" + extendedKeyUsageExtension + ", " : "")
                + (null != keyUsageExtension ? "keyUsageExtension=" + keyUsageExtension + ", " : "") + (null != certificateProfile ? "certificateProfile=" + certificateProfile + ", " : "")
                + (null != trustProfiles ? "trustProfiles=" + trustProfiles : "") + (null != subjectUniqueIdentifierValue ? "subjectUniqueIdentifierValue=" + subjectUniqueIdentifierValue : "") + "]";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((certificateProfile == null) ? 0 : certificateProfile.hashCode());
        result = prime * result + ((extendedKeyUsageExtension == null) ? 0 : extendedKeyUsageExtension.hashCode());
        result = prime * result + ((keyGenerationAlgorithm == null) ? 0 : keyGenerationAlgorithm.hashCode());
        result = prime * result + ((keyUsageExtension == null) ? 0 : keyUsageExtension.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((subjectAltNameExtension == null) ? 0 : subjectAltNameExtension.hashCode());
        result = prime * result + ((category == null) ? 0 : category.hashCode());
        result = prime * result + ((trustProfiles == null) ? 0 : trustProfiles.hashCode());
        result = prime * result + ((subjectUniqueIdentifierValue == null) ? 0 : subjectUniqueIdentifierValue.hashCode());
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
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final EntityProfile other = (EntityProfile) obj;
        if (extendedKeyUsageExtension == null) {
            if (other.extendedKeyUsageExtension != null) {
                return false;
            }
        } else if (!extendedKeyUsageExtension.equals(other.extendedKeyUsageExtension)) {
            return false;
        }
        if (keyUsageExtension == null) {
            if (other.keyUsageExtension != null) {
                return false;
            }
        } else if (!keyUsageExtension.equals(other.keyUsageExtension)) {
            return false;
        }
        if (keyGenerationAlgorithm == null) {
            if (other.keyGenerationAlgorithm != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithm.equals(other.keyGenerationAlgorithm)) {
            return false;
        }
        if (subject == null) {
            if (other.subject != null) {
                return false;
            }
        } else if (!subject.equals(other.subject)) {
            return false;
        }
        if (subjectAltNameExtension == null) {
            if (other.subjectAltNameExtension != null) {
                return false;
            }
        } else if (!subjectAltNameExtension.equals(other.subjectAltNameExtension)) {
            return false;
        }
        if (category == null) {
            if (other.category != null) {
                return false;
            }
        } else if (!category.equals(other.category)) {
            return false;
        }
        if (certificateProfile == null) {
            if (other.certificateProfile != null) {
                return false;
            }
        } else if (!certificateProfile.equals(other.certificateProfile)) {
            return false;
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
        if (subjectUniqueIdentifierValue == null) {
            if (other.subjectUniqueIdentifierValue != null) {
                return false;
            }
        } else if (!subjectUniqueIdentifierValue.equals(other.subjectUniqueIdentifierValue)) {
            return false;
        }

        return true;
    }
}
