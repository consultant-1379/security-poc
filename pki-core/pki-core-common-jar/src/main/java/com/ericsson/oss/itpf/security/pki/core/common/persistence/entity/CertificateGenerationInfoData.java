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

import javax.persistence.*;
import javax.validation.constraints.Size;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;

@Entity
@Table(name = "certificate_generation_info")
@SuppressWarnings("PMD.TooManyFields")
public class CertificateGenerationInfoData implements Serializable {

    private static final long serialVersionUID = 280945575795280108L;

    @Id
    private long id;

    @Column(name = "certificate_version", nullable = false)
    private Integer certificateVersion;

    @Column(name = "skew_certificate_time")
    @Size(max = 10)
    private String skewCertificateTime;

    @Column(nullable = false)
    @Size(max = 15)
    private String validity;

    @Column(name = "subject_unique_identifier", nullable = false)
    private boolean subjectUniqueIdentifier;

    @Column(name = "subject_unique_identifier_value", nullable = true)
    private String subjectUniqueIdentifierValue;

    @Column(name = "issuer_unique_identifier", nullable = false)
    private boolean issuerUniqueIdentifier;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "key_generation_algorithm", nullable = false)
    private AlgorithmData keyGenerationAlgorithmData;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "signature_algorithm", nullable = false)
    private AlgorithmData signatureAlgorithmData;
    
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_signature_algorithm", nullable = true)
    private AlgorithmData issuerSignatureAlgorithmData;

    @Column(name = "request_type", nullable = false)
    private Integer requestType;

    // JSON String
    @Column(name = "certificate_extensions", columnDefinition = "TEXT")
    private String certificateExtensionsJSONData;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "ca_entity_info")
    private CertificateAuthorityData cAEntityInfo;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_ca")
    private CertificateAuthorityData issuerCA;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "entity_info")
    private EntityInfoData entityInfo;

    @OneToOne(fetch = FetchType.LAZY, cascade = { CascadeType.PERSIST })
    @JoinColumn(name = "certificate_request_id")
    private CertificateRequestData certificateRequestData;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "certificate_id")
    private CertificateData certificateData;

    @Column(name = "for_external_ca")
    private boolean forExternalCA;

    /**
     * @return the forExternalCA
     */
    public boolean isForExternalCA() {
        return forExternalCA;
    }

    /**
     * @param forExternalCA
     *            the forExternalCA to set
     */
    public void setForExternalCA(final boolean forExternalCA) {
        this.forExternalCA = forExternalCA;
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
     * @return the certificate version
     */
    public CertificateVersion getCertificateVersion() {
        return CertificateVersion.fromValue(this.certificateVersion);
    }

    /**
     * @param certificateVersion
     *            certificate version to be set.
     */
    public void setCertificateVersion(final CertificateVersion certificateVersion) {

        if (certificateVersion == null) {
            this.certificateVersion = null;
        } else {
            this.certificateVersion = certificateVersion.value();
        }
    }

    /**
     * @return the skewCertificateTime
     */
    public String getSkewCertificateTime() {
        return skewCertificateTime;
    }

    /**
     * @param skewCertificateTime
     *            the skewCertificateTime to set
     */
    public void setSkewCertificateTime(final String skewCertificateTime) {
        this.skewCertificateTime = skewCertificateTime;
    }

    /**
     * @return the validity
     */
    public String getValidity() {
        return validity;
    }

    /**
     * @param validity
     *            the validity to set
     */
    public void setValidity(final String validity) {
        this.validity = validity;
    }

    /**
     * @return the subjectUniqueIdentifier
     */
    public boolean isSubjectUniqueIdentifier() {
        return subjectUniqueIdentifier;
    }

    /**
     * @param subjectUniqueIdentifier
     *            the subjectUniqueIdentifier to set
     */
    public void setSubjectUniqueIdentifier(final boolean subjectUniqueIdentifier) {
        this.subjectUniqueIdentifier = subjectUniqueIdentifier;
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
     * @return the keyGenerationAlgorithmData
     */
    public AlgorithmData getKeyGenerationAlgorithmData() {
        return keyGenerationAlgorithmData;
    }

    /**
     * @param keyGenerationAlgorithmData
     *            the keyGenerationAlgorithmData to set
     */
    public void setKeyGenerationAlgorithmData(final AlgorithmData keyGenerationAlgorithmData) {
        this.keyGenerationAlgorithmData = keyGenerationAlgorithmData;
    }

    /**
     * @return the signatureAlgorithmData
     */
    public AlgorithmData getSignatureAlgorithmData() {
        return signatureAlgorithmData;
    }

    /**
     * @param signatureAlgorithmData
     *            the signatureAlgorithmData to set
     */
    public void setSignatureAlgorithmData(final AlgorithmData signatureAlgorithmData) {
        this.signatureAlgorithmData = signatureAlgorithmData;
    }
    
    /**
     * @return the issuerSignatureAlgorithmData
     */
    public AlgorithmData getIssuerSignatureAlgorithmData() {
        return issuerSignatureAlgorithmData;
    }

    /**
     * @param issuerSignatureAlgorithmData
     *            the issuerSignatureAlgorithmData to set
     */
    public void setIssuerSignatureAlgorithmData(final AlgorithmData issuerSignatureAlgorithmData) {
        this.issuerSignatureAlgorithmData = issuerSignatureAlgorithmData;
    }

    /**
     * @return the certificateExtensionsJSONData
     */
    public String getCertificateExtensionsJSONData() {
        return certificateExtensionsJSONData;
    }

    /**
     * @return the request type
     */
    public RequestType getRequestType() {
        return RequestType.getType(this.requestType);
    }

    /**
     * @param requestType
     *            request type to be set.
     */
    public void setRequestType(final RequestType requestType) {

        if (requestType == null) {
            this.requestType = null;
        } else {
            this.requestType = requestType.getId();
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
     * @param certificateExtensionsJSONData
     *            the certificateExtensionsJSONData to set
     */
    public void setCertificateExtensionsJSONData(final String certificateExtensionsJSONData) {
        this.certificateExtensionsJSONData = certificateExtensionsJSONData;
    }

    /**
     * @return the cAEntityInfo
     */
    public CertificateAuthorityData getcAEntityInfo() {
        return cAEntityInfo;
    }

    /**
     * @param cAEntityInfo
     *            the cAEntityInfo to set
     */
    public void setcAEntityInfo(final CertificateAuthorityData cAEntityInfo) {
        this.cAEntityInfo = cAEntityInfo;
    }

    /**
     * @return the issuerCA
     */
    public CertificateAuthorityData getIssuerCA() {
        return issuerCA;
    }

    /**
     * @param issuerCA
     *            the issuerCA to set
     */
    public void setIssuerCA(final CertificateAuthorityData issuerCA) {
        this.issuerCA = issuerCA;
    }

    /**
     * @return the entityInfo
     */
    public EntityInfoData getEntityInfo() {
        return entityInfo;
    }

    /**
     * @param entityInfo
     *            the entityInfo to set
     */
    public void setEntityInfo(final EntityInfoData entityInfo) {
        this.entityInfo = entityInfo;
    }

    /**
     * @return the certificateRequestData
     */
    public CertificateRequestData getCertificateRequestData() {
        return certificateRequestData;
    }

    /**
     * @param certificateRequestData
     *            the certificateRequestData to set
     */
    public void setCertificateRequestData(final CertificateRequestData certificateRequestData) {
        this.certificateRequestData = certificateRequestData;
    }

    /**
     * Returns the has code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((cAEntityInfo == null) ? 0 : cAEntityInfo.hashCode());
        result = prime * result + ((certificateExtensionsJSONData == null) ? 0 : certificateExtensionsJSONData.hashCode());
        result = prime * result + ((certificateRequestData == null) ? 0 : certificateRequestData.hashCode());
        result = prime * result + ((certificateVersion == null) ? 0 : certificateVersion.hashCode());
        result = prime * result + ((entityInfo == null) ? 0 : entityInfo.hashCode());
        result = prime * result + ((issuerCA == null) ? 0 : issuerCA.hashCode());
        result = prime * result + (issuerUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((keyGenerationAlgorithmData == null) ? 0 : keyGenerationAlgorithmData.hashCode());
        result = prime * result + ((signatureAlgorithmData == null) ? 0 : signatureAlgorithmData.hashCode());
        result = prime * result + ((issuerSignatureAlgorithmData == null) ? 0 : issuerSignatureAlgorithmData.hashCode());
        result = prime * result + ((skewCertificateTime == null) ? 0 : skewCertificateTime.hashCode());
        result = prime * result + (subjectUniqueIdentifier ? 1231 : 1237);
        result = prime * result + ((certificateVersion == null) ? 0 : certificateVersion.hashCode());
        result = prime * result + ((validity == null) ? 0 : validity.hashCode());
        result = prime * result + ((certificateData == null) ? 0 : certificateData.hashCode());
        result = prime * result + (forExternalCA ? 1231 : 1237);
        result = prime * result + ((subjectUniqueIdentifierValue == null) ? 0 : subjectUniqueIdentifierValue.hashCode());
        return result;
    }

    /**
     * Indicates whether the invoking object is "equal to" the parameterized object
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
        final CertificateGenerationInfoData other = (CertificateGenerationInfoData) obj;
        if (cAEntityInfo == null) {
            if (other.cAEntityInfo != null) {
                return false;
            }
        } else if (!cAEntityInfo.equals(other.cAEntityInfo)) {
            return false;
        }
        if (certificateExtensionsJSONData == null) {
            if (other.certificateExtensionsJSONData != null) {
                return false;
            }
        } else if (!certificateExtensionsJSONData.equals(other.certificateExtensionsJSONData)) {
            return false;
        }
        if (certificateRequestData == null) {
            if (other.certificateRequestData != null) {
                return false;
            }
        } else if (!certificateRequestData.equals(other.certificateRequestData)) {
            return false;
        }
        if (certificateVersion == null) {
            if (other.certificateVersion != null) {
                return false;
            }
        } else if (!certificateVersion.equals(other.certificateVersion)) {
            return false;
        }
        if (entityInfo == null) {
            if (other.entityInfo != null) {
                return false;
            }
        } else if (!entityInfo.equals(other.entityInfo)) {
            return false;
        }
        if (issuerCA == null) {
            if (other.issuerCA != null) {
                return false;
            }
        } else if (!issuerCA.equals(other.issuerCA)) {
            return false;
        }
        if (issuerUniqueIdentifier != other.issuerUniqueIdentifier) {
            return false;
        }
        if (keyGenerationAlgorithmData == null) {
            if (other.keyGenerationAlgorithmData != null) {
                return false;
            }
        } else if (!keyGenerationAlgorithmData.equals(other.keyGenerationAlgorithmData)) {
            return false;
        }
        if (signatureAlgorithmData == null) {
            if (other.signatureAlgorithmData != null) {
                return false;
            }
        } else if (!signatureAlgorithmData.equals(other.signatureAlgorithmData)) {
            return false;
        }
        if (issuerSignatureAlgorithmData == null) {
            if (other.issuerSignatureAlgorithmData != null) {
                return false;
            }
        } else if (!issuerSignatureAlgorithmData.equals(other.issuerSignatureAlgorithmData)) {
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
        if (forExternalCA != other.forExternalCA) {
            return false;
        }
        if (certificateVersion != other.certificateVersion) {
            return false;
        }
        if (validity == null) {
            if (other.validity != null) {
                return false;
            }
        } else if (!validity.equals(other.validity)) {
            return false;
        }
        if (certificateData == null) {
            if (other.certificateData != null) {
                return false;
            }
        } else if (!certificateData.equals(other.certificateData)) {
            return false;
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

    /**
     * Returns string representation of {@link CertificateGenerationInfoData} object.
     */
    @Override
    public String toString() {
        return "CertificateGenerationInfoData [certificateVersion=" + certificateVersion + ", skewCertificateTime=" + skewCertificateTime + ", validity=" + validity + ", subjectUniqueIdentifier="
                + subjectUniqueIdentifier + ", issuerUniqueIdentifier=" + issuerUniqueIdentifier + ", subjectUniqueIdentifierValue="+subjectUniqueIdentifierValue+", keyGenerationAlgorithmData=" + keyGenerationAlgorithmData + ", signatureAlgorithmData="
                + signatureAlgorithmData + ", issuerSignatureAlgorithmData= "+ issuerSignatureAlgorithmData + ", requestType=" + certificateVersion + ", certificateExtensionsJSONData=" + certificateExtensionsJSONData + ", cAEntityInfo=" + cAEntityInfo
                + ", issuerCA=" + issuerCA + ", entityInfo=" + entityInfo + ", certificateRequestData=" + certificateRequestData + ", certificateData=" + certificateData + ", forExternalCA="
                + forExternalCA + ", subjectUniqueIdentifierValue=" + subjectUniqueIdentifierValue + "]";
    }
}
