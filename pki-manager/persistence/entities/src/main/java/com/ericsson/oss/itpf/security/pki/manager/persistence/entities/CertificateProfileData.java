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
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;
import javax.validation.constraints.Size;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;

@Entity
@Table(name = "CertificateProfile")
public class CertificateProfileData extends AbstractProfileData implements Serializable {

    private static final long serialVersionUID = 7696424500303656964L;

    @Column(name = "version_id", nullable = false)
    private Integer version;

    @ManyToOne(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "signature_algorithm_id", nullable = false)
    private AlgorithmData signatureAlgorithm;

    @ManyToMany(fetch = FetchType.EAGER, cascade = { CascadeType.REFRESH })
    @JoinTable(name = "CertificateProfile_KeyGenerationAlgorithm", joinColumns = @JoinColumn(name = "certificate_profile_id"), inverseJoinColumns = @JoinColumn(name = "key_generation_algorithm_id"))
    private Set<AlgorithmData> keyGenerationAlgorithms = new HashSet<AlgorithmData>();

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "issuer_id", nullable = true)
    private CAEntityData issuerData;

    @Column(nullable = false)
    @Size(max = 10)
    private String validity;

    @Column(name = "subject_unique_identifier", nullable = false)
    private boolean subjectUniqueIdentifier;

    @Column(name = "issuer_unique_identifier", nullable = false)
    private boolean issuerUniqueIdentifier;

    @Column(name = "skew_certificate_time", nullable = true)
    @Size(max = 10)
    private String skewCertificateTime;

    // JSON String
    @Column(name = "Certificate_Extensions", nullable = true, columnDefinition = "TEXT")
    private String certificateExtensionsJSONData;

    @Column(name = "subject_capabilities", columnDefinition = "TEXT")
    private String subjectCapabilities;

    @Column(name = "for_ca_entity", nullable = false)
    private boolean forCAEntity;

    /**
     * @return the certificateVersion
     */
    public CertificateVersion getVersion() {
        return CertificateVersion.fromValue(this.version);
    }

    /**
     * @param certificateVersion
     *            the certificateVersion to set
     */
    public void setVersion(final CertificateVersion certificateVersion) {
        if (certificateVersion == null) {
            this.version = null;
        } else {
            this.version = certificateVersion.value();
        }
    }

    public AlgorithmData getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(final AlgorithmData signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public Set<AlgorithmData> getKeyGenerationAlgorithms() {
        return keyGenerationAlgorithms;
    }

    public void setKeyGenerationAlgorithms(final Set<AlgorithmData> keyGenerationAlgorithms) {
        this.keyGenerationAlgorithms = keyGenerationAlgorithms;
    }

    public CAEntityData getIssuerData() {
        return issuerData;
    }

    public void setIssuerData(final CAEntityData issuerData) {
        this.issuerData = issuerData;
    }

    public String getValidity() {
        return validity;
    }

    public void setValidity(final String validity) {
        this.validity = validity;
    }

    public boolean isSubjectUniqueIdentifier() {
        return subjectUniqueIdentifier;
    }

    public void setSubjectUniqueIdentifier(final boolean subjectUniqueIdentifier) {
        this.subjectUniqueIdentifier = subjectUniqueIdentifier;
    }

    public boolean isIssuerUniqueIdentifier() {
        return issuerUniqueIdentifier;
    }

    public void setIssuerUniqueIdentifier(final boolean issuerUniqueIdentifier) {
        this.issuerUniqueIdentifier = issuerUniqueIdentifier;
    }

    public String getSkewCertificateTime() {
        return skewCertificateTime;
    }

    public void setSkewCertificateTime(final String skewCertificateTime) {
        this.skewCertificateTime = skewCertificateTime;
    }

    public String getCertificateExtensionsJSONData() {
        return certificateExtensionsJSONData;
    }

    public void setCertificateExtensionsJSONData(final String certificateExtensionsJSONData) {
        this.certificateExtensionsJSONData = certificateExtensionsJSONData;
    }

    public String getSubjectCapabilities() {
        return subjectCapabilities;
    }

    public void setSubjectCapabilities(final String subjectCapabilities) {
        this.subjectCapabilities = subjectCapabilities;
    }

    /**
     * @return the cAEntity
     */
    public boolean isForCAEntity() {
        return forCAEntity;
    }

    /**
     * @param cAEntity
     *            the cAEntity to set
     */
    public void setForCAEntity(final boolean forCAEntity) {
        this.forCAEntity = forCAEntity;
    }

    /**
     * Returns a hash code value for the object
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((certificateExtensionsJSONData == null) ? 0 : certificateExtensionsJSONData.hashCode());
        result = prime * result + ((subjectCapabilities == null) ? 0 : subjectCapabilities.hashCode());
        result = prime * result + (forCAEntity ? 1231 : 1237);
        result = prime * result + (issuerUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((keyGenerationAlgorithms == null) ? 0 : keyGenerationAlgorithms.hashCode());
        result = prime * result + ((signatureAlgorithm == null) ? 0 : signatureAlgorithm.hashCode());
        result = prime * result + ((skewCertificateTime == null) ? 0 : skewCertificateTime.hashCode());
        result = prime * result + (subjectUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((validity == null) ? 0 : validity.hashCode());
        result = prime * result + ((version == null) ? 0 : version.hashCode());
        return result;
    }

    /**
     * returns whether the invoking object is "equal to" the parameterized object
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

        final CertificateProfileData other = (CertificateProfileData) obj;

        if (certificateExtensionsJSONData == null) {
            if (other.certificateExtensionsJSONData != null) {
                return false;
            }
        } else if (!certificateExtensionsJSONData.equals(other.certificateExtensionsJSONData)) {
            return false;
        }

        if (subjectCapabilities == null) {
            if (other.subjectCapabilities != null) {
                return false;
            }
        } else if (!subjectCapabilities.equals(other.subjectCapabilities)) {
            return false;
        }

        if (forCAEntity != other.forCAEntity) {
            return false;
        }
        if (issuerData == null) {
            if (other.issuerData != null) {
                return false;
            }
        } else if (!issuerData.equals(other.issuerData)) {
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
            boolean isMatched = false;
            for (final AlgorithmData keyGenerationAlgorithm : keyGenerationAlgorithms) {
                for (final AlgorithmData keyGenerationAlgorithmOther : other.keyGenerationAlgorithms) {
                    if (keyGenerationAlgorithm.equals(keyGenerationAlgorithmOther)) {
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
        if (validity == null) {
            if (other.validity != null) {
                return false;
            }
        } else if (!validity.equals(other.validity)) {
            return false;
        }
        if (version != other.version) {
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
        return super.toString() + "CertificateProfileData [" + (version != null ? "version=" + version + ", " : "")
                + (signatureAlgorithm != null ? "signatureAlgorithm=" + signatureAlgorithm + ", " : "")
                + (keyGenerationAlgorithms != null ? "keyGenerationAlgorithms=" + keyGenerationAlgorithms + ", " : "")
                + (issuerData != null ? "issuerData=" + issuerData.getCertificateAuthorityData().getName() + ", " : "") + (validity != null ? "validity=" + validity + ", " : "")
                + "subjectUniqueIdentifier=" + subjectUniqueIdentifier + ", issuerUniqueIdentifier=" + issuerUniqueIdentifier + ", "
                + (skewCertificateTime != null ? "skewCertificateTime=" + skewCertificateTime + ", " : "")
                + (certificateExtensionsJSONData != null ? "certificateExtensionsJSONData=" + certificateExtensionsJSONData + ", " : "")
                + (subjectCapabilities != null ? "subjectCapabilities=" + subjectCapabilities + ", " : "") + "forCAEntity=" + forCAEntity + "]";
    }

}
