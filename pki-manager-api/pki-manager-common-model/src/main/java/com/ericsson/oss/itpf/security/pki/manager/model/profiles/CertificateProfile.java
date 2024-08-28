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
import javax.xml.datatype.Duration;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * <p>
 * A certificate profile is a description of a set of configuration that can be applied for a set of certificates. This makes it possible for one CA to issue certificates to different purposes. For
 * example, the same CA can issue certificates for pRBS and mRBS nodes, but with different signature/hashing algorithm or with different certificate extension fields. All of these settings must be
 * defined in the certificate profile.
 * 
 * The certificate profile with this functionality makes it possible to manage different OSSs (if there will be any).
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateProfile">
 *   &lt;complexContent>
 *     &lt;extension base="{}AbstractProfile">
 *       &lt;sequence>
 *         &lt;element name="ForCAEntity" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="Version" type="{}CertificateVersion"/>
 *         &lt;element name="SignatureAlgorithm" type="{}Algorithm"/>
 *         &lt;element name="KeyGenerationAlgorithm" type="{}Algorithm" maxOccurs="unbounded"/>
 *         &lt;element name="Validity" type="{http://www.w3.org/2001/XMLSchema}duration"/>
 *         &lt;element name="Issuer" type="{}CAEntity" minOccurs="0"/>
 *         &lt;element name="SubjectUniqueIdentifier" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="IssuerUniqueIdentifier" type="{http://www.w3.org/2001/XMLSchema}boolean" minOccurs="0"/>
 *         &lt;element name="SkewCertificateTime" type="{http://www.w3.org/2001/XMLSchema}duration" minOccurs="0"/>
 *         &lt;element name="CertificateExtensions" type="{}CertificateExtensionMapModeller"/>
 *         &lt;element name="SubjectCapabilities" type="{}SubjectCapabilities"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "CertificateProfile")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateProfile", propOrder = { "forCAEntity", "version", "signatureAlgorithm", "keyGenerationAlgorithms", "certificateValidity", "issuer", "subjectUniqueIdentifier",
        "issuerUniqueIdentifier", "skewCertificateTime", "certificateExtensions", "subjectCapabilities" })
public class CertificateProfile extends AbstractProfile implements Serializable {

    /**
         * 
         */
    private static final long serialVersionUID = 3177521284798669595L;

    @XmlElement(name = "ForCAEntity", required = true)
    protected boolean forCAEntity;
    @XmlElement(name = "Version", required = true)
    protected CertificateVersion version;
    @XmlElement(name = "SignatureAlgorithm", required = true)
    protected Algorithm signatureAlgorithm;
    @XmlElement(name = "KeyGenerationAlgorithm", required = true)
    protected List<Algorithm> keyGenerationAlgorithms = new ArrayList<Algorithm>();
    @XmlElement(name = "CertificateValidity", required = true)
    protected Duration certificateValidity;
    @XmlElement(name = "Issuer", required = false)
    protected CAEntity issuer;
    @XmlElement(name = "SubjectUniqueIdentifier", required = false)
    protected boolean subjectUniqueIdentifier;
    @XmlElement(name = "IssuerUniqueIdentifier", required = false)
    protected boolean issuerUniqueIdentifier;
    @XmlElement(name = "SkewCertificateTime", required = false)
    protected Duration skewCertificateTime;
    @XmlElement(name = "CertificateExtensions", required = false)
    protected CertificateExtensions certificateExtensions;
    @XmlElement(name = "SubjectCapabilities", required = true)
    protected Subject subjectCapabilities;

    public CertificateProfile() {
        setType(ProfileType.CERTIFICATE_PROFILE);
    }

    /**
     * @return the CAEntity
     */
    public boolean isForCAEntity() {
        return forCAEntity;
    }

    /**
     * @param CAEntity
     *            the cAEntity to set
     */
    public void setForCAEntity(final boolean cAEntity) {
        this.forCAEntity = cAEntity;
    }

    /**
     * Gets the value of the certificateVersion property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public CertificateVersion getVersion() {
        return version;
    }

    /**
     * Sets the value of the certificateVersion property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setVersion(final CertificateVersion value) {
        this.version = value;
    }

    /**
     * Gets the value of the signatureAlgorithm property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public Algorithm getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Sets the value of the signatureAlgorithm property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setSignatureAlgorithm(final Algorithm value) {
        this.signatureAlgorithm = value;
    }

    /**
     * Gets the value of the keyGenerationAlgorithm property.
     * 
     * <p>
     * This accessor method returns a reference to the live list, not a snapshot. Therefore any modification you make to the returned list will be present inside the JAXB object. This is why there is
     * not a <CODE>set</CODE> method for the keyGenerationAlgorithm property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * 
     * <pre>
     * getKeyGenerationAlgorithm().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list {@link Algorithm }
     * 
     * 
     */
    public List<Algorithm> getKeyGenerationAlgorithms() {
        if (keyGenerationAlgorithms == null) {
            keyGenerationAlgorithms = new ArrayList<Algorithm>();
        }
        return this.keyGenerationAlgorithms;
    }

    /**
     * Sets the value of the keyGenerationAlgorithm property.
     * 
     * @param keyGenerationAlgorithm
     *            the keyGenerationAlgorithm to set
     */
    public void setKeyGenerationAlgorithms(final List<Algorithm> keygenerationAlgorithms) {
        this.keyGenerationAlgorithms = keygenerationAlgorithms;
    }

    /**
     * @return the certificateValidity
     */
    public Duration getCertificateValidity() {
        return certificateValidity;
    }

    /**
     * @param certificateValidity
     *            the certificateValidity to set
     */
    public void setCertificateValidity(final Duration certificateValidity) {
        this.certificateValidity = certificateValidity;
    }

    /**
     * @return the issuerDetails
     */
    public CAEntity getIssuer() {
        return issuer;
    }

    /**
     * @param issuerDetails
     *            the issuerDetails to set
     */
    public void setIssuer(final CAEntity issuer) {
        this.issuer = issuer;
    }

    /**
     * @param subjectUniqueIdentifier
     *            the subjectUniqueIdentifier to set
     */
    public void setSubjectUniqueIdentifier(final boolean subjectUniqueIdentifier) {
        this.subjectUniqueIdentifier = subjectUniqueIdentifier;
    }

    /**
     * @return the subjectUniqueIdentifier
     */
    public boolean isSubjectUniqueIdentifier() {
        return subjectUniqueIdentifier;
    }

    /**
     * @return the issuerUniqueIdentifier
     */
    public boolean isIssuerUniqueIdentifier() {
        return issuerUniqueIdentifier;
    }

    /**
     * @param issuerUniqueIdentifier
     *            the issuerUniqueIdentifier to set
     */
    public void setIssuerUniqueIdentifier(final boolean issuerUniqueIdentifier) {
        this.issuerUniqueIdentifier = issuerUniqueIdentifier;
    }

    /**
     * @return the skewCertificateTime
     */
    public Duration getSkewCertificateTime() {
        return skewCertificateTime;
    }

    /**
     * @param skewCertificateTime
     *            the skewCertificateTime to set
     */
    public void setSkewCertificateTime(final Duration skewCertificateTime) {
        this.skewCertificateTime = skewCertificateTime;
    }

    /**
     * @return the certificateExtensions
     */
    public CertificateExtensions getCertificateExtensions() {
        return certificateExtensions;
    }

    /**
     * @param certificateExtensions
     *            the certificateExtensions to set
     */
    public void setCertificateExtensions(final CertificateExtensions certificateExtensions) {
        this.certificateExtensions = certificateExtensions;
    }

    /**
     * @return the subjectCapabilities
     */
    public Subject getSubjectCapabilities() {
        return subjectCapabilities;
    }

    /**
     * @param subjectCapabilities
     *            the subjectCapabilities to set
     */
    public void setSubjectCapabilities(final Subject subjectCapabilities) {
        this.subjectCapabilities = subjectCapabilities;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "CertificateProfile [" + super.toString() + ", " + "forCAEntity=" + forCAEntity + ", " + (null != version ? "version=" + version + ", " : "")
                + (null != signatureAlgorithm ? "signatureAlgorithm=" + signatureAlgorithm + ", " : "")
                + (null != keyGenerationAlgorithms ? "keyGenerationAlgorithms=" + keyGenerationAlgorithms + ", " : "")
                + (null != certificateValidity ? "certificateValidity=" + certificateValidity + ", " : "") + "subjectUniqueIdentifier=" + subjectUniqueIdentifier + ", issuerUniqueIdentifier="
                + issuerUniqueIdentifier + ", " + (null != skewCertificateTime ? "skewCertificateTime=" + skewCertificateTime + ", " : "")
                + (null != certificateExtensions ? "certificateExtensions=" + certificateExtensions + ", " : "") + (null != issuer ? "issuer=" + issuer : "")
                + (null != subjectCapabilities ? " subjectCapabilities=" + subjectCapabilities + ", " : "") + "]";
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
        result = prime * result + ((certificateExtensions == null) ? 0 : certificateExtensions.hashCode());
        result = prime * result + ((subjectCapabilities == null) ? 0 : subjectCapabilities.hashCode());
        result = prime * result + ((certificateValidity == null) ? 0 : certificateValidity.hashCode());
        result = prime * result + (forCAEntity ? 1231 : 1237);
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + (issuerUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((keyGenerationAlgorithms == null) ? 0 : keyGenerationAlgorithms.hashCode());
        result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
        result = prime * result + ((skewCertificateTime == null) ? 0 : skewCertificateTime.hashCode());
        result = prime * result + (subjectUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((version == null) ? 0 : version.hashCode());
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
        final CertificateProfile other = (CertificateProfile) obj;
        if (certificateExtensions == null) {
            if (other.certificateExtensions != null) {
                return false;
            }
        } else if (!certificateExtensions.equals(other.certificateExtensions)) {
            return false;
        }
        if (subjectCapabilities == null) {
            if (other.subjectCapabilities != null) {
                return false;
            }
        } else if (!subjectCapabilities.equals(other.subjectCapabilities)) {
            return false;
        }
        if (certificateValidity == null) {
            if (other.certificateValidity != null) {
                return false;
            }
        } else if (!certificateValidity.equals(other.certificateValidity)) {
            return false;
        }
        if (forCAEntity != other.forCAEntity) {
            return false;
        }
        if (issuer == null) {
            if (other.issuer != null) {
                return false;
            }
        } else if (!issuer.equals(other.issuer)) {
            return false;
        }
        if (issuerUniqueIdentifier != other.issuerUniqueIdentifier) {
            return false;
        }
        if (keyGenerationAlgorithms == null) {
            if (other.keyGenerationAlgorithms != null) {
                return false;
            }
        } else if (keyGenerationAlgorithms.size() != other.keyGenerationAlgorithms.size()) {
            return false;
        } else if (keyGenerationAlgorithms != null && other.keyGenerationAlgorithms != null) {
            boolean algorithmFound = false;
            for (final Algorithm algorithm : keyGenerationAlgorithms) {
                for (final Algorithm algorithmOther : other.keyGenerationAlgorithms) {
                    if (algorithm.getName().equals(algorithmOther.getName())) {
                        algorithmFound = true;
                        if (!algorithm.equals(algorithmOther)) {
                            return false;
                        }
                    }
                }
                if (!algorithmFound) {
                    return false;
                }
                algorithmFound = false;
            }
        }
        if (signatureAlgorithm == null) {
            if (other.signatureAlgorithm != null) {
                return false;
            }
        } else if (!signatureAlgorithm.equals(other.signatureAlgorithm)) {
            return false;
        }
        if (skewCertificateTime == null) {
            if (other.skewCertificateTime != null) {
                return false;
            }
        } else if (!skewCertificateTime.equals(other.skewCertificateTime)) {
            return false;
        }
        if (subjectUniqueIdentifier != other.subjectUniqueIdentifier) {
            return false;
        }
        if (version != other.version) {
            return false;
        }
        return true;
    }

}
