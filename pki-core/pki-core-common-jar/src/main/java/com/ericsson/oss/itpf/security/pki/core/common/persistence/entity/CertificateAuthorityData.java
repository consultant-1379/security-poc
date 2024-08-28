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
import java.util.*;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;

@Entity
@Table(name = "certificate_authority")
public class CertificateAuthorityData implements Serializable {

    private static final long serialVersionUID = 6120986385175610220L;

    @Id
    private long id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(name = "is_root_ca", nullable = false)
    private boolean rootCA;

    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "issuer_id")
    private CertificateAuthorityData issuerCA;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @Column(name = "subject_dn", columnDefinition = "TEXT")
    private String subjectDN;

    @Column(name = "subject_alt_name", columnDefinition = "TEXT")
    private String subjectAltName;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(name = "CA_CERTIFICATE", joinColumns = @JoinColumn(name = "ca_id"), inverseJoinColumns = @JoinColumn(name = "certificate_id"))
    private Set<CertificateData> certificateDatas = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinTable(name = "CA_KEYS", joinColumns = @JoinColumn(name = "ca_id"), inverseJoinColumns = @JoinColumn(name = "key_id"))
    private Set<KeyIdentifierData> cAKeys = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.ALL })
    @JoinTable(name = "CA_CRLINFO", joinColumns = @JoinColumn(name = "ca_id"), inverseJoinColumns = @JoinColumn(name = "crlinfo_id"))
    private Set<CRLInfoData> crlInfoDatas = new HashSet<>();

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(name = "CA_CRL_GENERATION_INFO", joinColumns = @JoinColumn(name = "caentity_id"), inverseJoinColumns = @JoinColumn(name = "crl_generation_info_id"))
    private Set<CrlGenerationInfoData> crlGenerationInfo = new HashSet<>();

    @Column(name = "publish_to_cdps", nullable = false)
    private boolean publishToCDPS;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;

    @Column(name = "is_issuer_external_ca")
    private boolean isIssuerExternalCA;

    /**
     * @return the isIssuerExternalCA
     */
    public boolean isIssuerExternalCA() {
        return isIssuerExternalCA;
    }

    /**
     * @param isIssuerExternalCA
     *            the isIssuerExternalCA to set
     */
    public void setIssuerExternalCA(final boolean isIssuerExternalCA) {
        this.isIssuerExternalCA = isIssuerExternalCA;
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
     * @return the rootCA
     */
    public boolean isRootCA() {
        return rootCA;
    }

    /**
     * @param rootCA
     *            the rootCA to set
     */
    public void setRootCA(final boolean rootCA) {
        this.rootCA = rootCA;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public void setName(final String name) {
        this.name = name;
    }

    /**
     * @return the CA Status
     */
    public CAStatus getStatus() {
        return CAStatus.getStatus(this.status);
    }

    /**
     * @param cAStatus
     *            certificate status to be set.
     */
    public void setStatus(final CAStatus cAStatus) {

        if (cAStatus == null) {
            this.status = null;
        } else {
            this.status = cAStatus.getId();
        }
    }

    /**
     * @return the certificateDatas
     */
    public Set<CertificateData> getCertificateDatas() {
        return certificateDatas;
    }

    /**
     * @param certificateDatas
     *            the certificateDatas to set
     */
    public void setCertificateDatas(final Set<CertificateData> certificateDatas) {
        this.certificateDatas = certificateDatas;
    }

    /**
     * @return the subjectDN
     */
    public String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @param subjectDN
     *            the subjectDN to set
     */
    public void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * @return the subjectAltName
     */
    public String getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltName(final String subjectAltName) {
        this.subjectAltName = subjectAltName;
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
     * @return the cAKeys
     */
    public Set<KeyIdentifierData> getcAKeys() {
        return cAKeys;
    }

    /**
     * @param cAKeys
     *            the cAKeys to set
     */
    public void setcAKeys(final Set<KeyIdentifierData> cAKeys) {
        this.cAKeys = cAKeys;
    }

    /**
     * @return the crlDatas
     */
    public Set<CRLInfoData> getCrlInfoDatas() {
        return crlInfoDatas;
    }

    /**
     * @param crlDatas
     *            the crlDatas to set
     */
    public void setCrlDatas(final Set<CRLInfoData> crlDatas) {
        this.crlInfoDatas = crlDatas;
    }

    /**
     * @return the crlGenerationInfo
     */
    public Set<CrlGenerationInfoData> getCrlGenerationInfo() {
        return crlGenerationInfo;
    }

    /**
     * @param crlGenerationInfo
     *            the crlGenerationInfo to set
     */
    public void setCrlGenerationInfo(final Set<CrlGenerationInfoData> crlGenerationInfo) {
        this.crlGenerationInfo = crlGenerationInfo;
    }

    /**
     * @return the publishToCDPS
     */
    public boolean isPublishToCDPS() {
        return publishToCDPS;
    }

    /**
     * @param publishToCDPS
     *            the publishToCDPS to set
     */
    public void setPublishToCDPS(final boolean publishToCDPS) {
        this.publishToCDPS = publishToCDPS;
    }

    /**
     * @return the createdDate
     */
    public Date getCreatedDate() {
        return createdDate;
    }

    /**
     * @param createdDate
     *            the createdDate to set
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
     * @param modifiedDate
     *            the modifiedDate to set
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    /**
     * Sets current timestamp to createdDate and modifiedDate before persisting in DB.
     */
    @PrePersist
    protected void onCreate() {
        createdDate = new Date();
        modifiedDate = new Date();
    }

    /**
     * Sets current timestamp to modifiedDate before updating in DB
     */
    @PreUpdate
    protected void onUpdate() {
        modifiedDate = new Date();
    }

    /**
     * Returns the has code of object.
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + (rootCA ? 1231 : 1237);
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());

        // result = prime * result + ((certificateDatas == null) ? 0 : certificateDatas.hashCode());
        // result = prime * result + ((cAKeys == null) ? 0 : cAKeys.hashCode());
        result = prime * result + ((crlInfoDatas == null) ? 0 : crlInfoDatas.hashCode());
        result = prime * result + ((crlGenerationInfo == null) ? 0 : crlGenerationInfo.hashCode());
        result = prime * result + (publishToCDPS ? 1231 : 1237);
        result = prime * result + (isIssuerExternalCA ? 1231 : 1237);
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
        final CertificateAuthorityData other = (CertificateAuthorityData) obj;
        if (certificateDatas == null) {
            if (other.certificateDatas != null) {
                return false;
            }
        } else if (certificateDatas != null && other.certificateDatas == null) {
            return false;
        } else if (certificateDatas != null && other.certificateDatas != null) {
            if (certificateDatas.size() != other.certificateDatas.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CertificateData certificateData : certificateDatas) {
                for (final CertificateData certificateDataOther : other.certificateDatas) {
                    if (certificateData.equals(certificateDataOther)) {
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
        if (crlInfoDatas == null) {
            if (other.crlInfoDatas != null) {
                return false;
            }
        } else if (crlInfoDatas != null && other.crlInfoDatas == null) {
            return false;
        } else if (crlInfoDatas != null && other.crlInfoDatas != null) {
            if (crlInfoDatas.size() != other.crlInfoDatas.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CRLInfoData crlData : crlInfoDatas) {
                for (final CRLInfoData crlDataOther : other.crlInfoDatas) {
                    if (crlData.equals(crlDataOther)) {
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

        if (cAKeys == null) {
            if (other.cAKeys != null) {
                return false;
            }
        } else if (cAKeys != null && other.cAKeys == null) {
            return false;
        } else if (cAKeys != null && other.cAKeys != null) {
            if (cAKeys.size() != other.cAKeys.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final KeyIdentifierData keyData : cAKeys) {
                for (final KeyIdentifierData keyDataOther : other.cAKeys) {
                    if (keyData.equals(keyDataOther)) {
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
        if (id != other.id) {
            return false;
        }
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (rootCA != other.rootCA) {
            return false;
        }
        if (!status.equals(other.status)) {
            return false;
        }
        if (this.getSubjectAltName() == null) {
            if (other.getSubjectAltName() != null) {
                return false;
            }
        } else if (!this.getSubjectAltName().equals(other.getSubjectAltName())) {
            return false;
        }
        if (this.getSubjectDN() == null) {
            if (other.getSubjectDN() != null) {
                return false;
            }
        } else if (!this.getSubjectDN().equals(other.getSubjectDN())) {
            return false;
        }
        if (crlGenerationInfo == null) {
            if (other.crlGenerationInfo != null) {
                return false;
            }
        } else if (crlGenerationInfo != null && other.crlGenerationInfo == null) {
            return false;
        } else if (crlGenerationInfo != null && other.crlGenerationInfo != null) {
            if (crlGenerationInfo.size() != other.crlGenerationInfo.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CrlGenerationInfoData crlGenerationData : crlGenerationInfo) {
                for (final CrlGenerationInfoData CrlGenerationInfoDataOther : other.crlGenerationInfo) {
                    if (crlGenerationData.equals(CrlGenerationInfoDataOther)) {
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
        if (publishToCDPS != other.publishToCDPS) {
            return false;
        }
        if (isIssuerExternalCA != other.isIssuerExternalCA) {
            return false;
        }

        return true;
    }

    /**
     * Returns string representation of {@link CertificateAuthorityData} object.
     */
    @Override
    public String toString() {
        return "CertificateAuthority [rootCA=" + rootCA + ", " + (null != name ? "name=" + name + ", " : "") + (null != status ? "status=" + status + ", " : "") + ", "
                + (null != subjectDN ? "subjectDN=" + subjectDN + ", " : "") + (null != crlInfoDatas ? "crlDatas=" + crlInfoDatas : "")
                + (null != subjectAltName ? "subjectAltName=" + subjectAltName : "") + (null != crlGenerationInfo ? "crlGenerationInfo=" + crlGenerationInfo : "") + ",publishToCDPS=" + publishToCDPS
                + ",isIssuerExternalCA=" + isIssuerExternalCA + "]";
    }
}
