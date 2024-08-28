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
import java.util.*;

import javax.persistence.*;

//TODO: Adding of CRLGenerationInfo will be done as part of  TORF-80129
@Embeddable
public class CertificateAuthorityData implements Serializable {

    private static final long serialVersionUID = 6120986385175610220L;

    @Column(name = "Name", nullable = false, unique = true)
    private String name;

    @Column(name = "is_root_ca", nullable = false)
    private boolean rootCA;

    @Column(name = "subject_dn", nullable = true, columnDefinition = "TEXT")
    private String subjectDN;

    @Column(name = "subject_alt_name", nullable = true, columnDefinition = "TEXT")
    private String subjectAltName;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "issuer_id", nullable = true)
    private CAEntityData issuer;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(name = "CA_CERTIFICATE", joinColumns = @JoinColumn(name = "ca_id"), inverseJoinColumns = @JoinColumn(name = "certificate_id"))
    private Set<CertificateData> certificateDatas = new HashSet<CertificateData>();

    // BEGIN dDU-TORF-47941 - DESPICABLE_US
    @OneToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST })
    @JoinColumn(name = "external_crl_info_id", nullable = true)
    private ExternalCRLInfoData externalCrlInfoData;
    // END dDU-TORF-47941 - DESPICABLE_US

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.ALL }, orphanRemoval = true)
    @JoinTable(name = "CA_CRLINFO", joinColumns = @JoinColumn(name = "ca_id"), inverseJoinColumns = @JoinColumn(name = "crlinfo_id"))
    private Set<CRLInfoData> cRLData = new HashSet<CRLInfoData>();

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.PERSIST, CascadeType.MERGE })
    @JoinTable(name = "CA_CRL_GENERATION_INFO", joinColumns = @JoinColumn(name = "caentity_id"), inverseJoinColumns = @JoinColumn(name = "crl_generation_info_id"))
    private Set<CrlGenerationInfoData> crlGenerationInfo = new HashSet<CrlGenerationInfoData>();

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
     * 
     * @param createdDate
     */
    public void setCreatedDate(final Date createdDate) {
        this.createdDate = createdDate;
    }

    /**
     * 
     * @param modifiedDate
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    /**
     * @return the createdDate
     */
    public Date getCreatedDate() {
        return createdDate;
    }

    /**
     * @return the modifiedDate
     */
    public Date getModifiedDate() {
        return modifiedDate;
    }

    public Integer getStatus() {
        return this.status;
    }

    public void setStatus(final Integer caStatus) {
        this.status = caStatus;
    }

    /**
     * @return the name
     */
    public final String getName() {
        return name;
    }

    /**
     * @param name
     *            the name to set
     */
    public final void setName(final String name) {
        this.name = name;
    }

    /**
     * @return the rootCA
     */
    public final boolean isRootCA() {
        return rootCA;
    }

    /**
     * @param rootCA
     *            the rootCA to set
     */
    public final void setRootCA(final boolean rootCA) {
        this.rootCA = rootCA;
    }

    /**
     * @return the subjectDN
     */
    public final String getSubjectDN() {
        return subjectDN;
    }

    /**
     * @param subjectDN
     *            the subjectDN to set
     */
    public final void setSubjectDN(final String subjectDN) {
        this.subjectDN = subjectDN;
    }

    /**
     * @return the subjectAltName
     */
    public final String getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public final void setSubjectAltName(final String subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    /**
     * @return the issuer
     */
    public final CAEntityData getIssuer() {
        return issuer;
    }

    /**
     * @param issuer
     *            the issuer to set
     */
    public final void setIssuer(final CAEntityData issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the certificateDatas
     */
    public final Set<CertificateData> getCertificateDatas() {
        return certificateDatas;
    }

    /**
     * @param certificateDatas
     *            the certificateDatas to set
     */
    public final void setCertificateDatas(final Set<CertificateData> certificateDatas) {
        this.certificateDatas = certificateDatas;
    }

    // BEGIN dDU-TORF-47941 - DESPICABLE_US
    /**
     * @return the ExternalCRLInfoData
     */
    public ExternalCRLInfoData getExternalCrlInfoData() {
        return externalCrlInfoData;
    }

    /**
     * @param externalCrlInfoData
     *            the crlData to set
     */
    public void setExternalCrlInfoData(final ExternalCRLInfoData externalCrlInfoData) {
        this.externalCrlInfoData = externalCrlInfoData;
    }

    /**
     * @return the cRLDatas
     */
    public Set<CRLInfoData> getcRLDatas() {
        return cRLData;
    }

    /**
     * @param cRLDatas
     *            the cRLDatas to set
     */
    public void setcRLDatas(final Set<CRLInfoData> cRLDatas) {
        this.cRLData = cRLDatas;
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

    @Override
    public String toString() {
        return "CertificateAuthorityData [" + (name != null ? "name=" + name + ", " : "") + "rootCA=" + rootCA + ", " + (subjectDN != null ? "subjectDN=" + subjectDN + ", " : "")
                + (subjectAltName != null ? "subjectAltName=" + subjectAltName + ", " : "") + (status != null ? "status=" + status + ", " : "") + (issuer != null ? "issuer=" + issuer + ", " : "")
                + (certificateDatas != null ? "certificateDatas=" + certificateDatas + ", " : "") + (externalCrlInfoData != null ? "externalCrlInfoData=" + externalCrlInfoData : "") + ", cRLData="
                + cRLData + " , crlGenerationInfo=" + crlGenerationInfo + " , publishToCDPS=" + publishToCDPS + " , isIssuerExternalCA=" + isIssuerExternalCA + "]";
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((certificateDatas == null) ? 0 : certificateDatas.hashCode());
        result = prime * result + ((externalCrlInfoData == null) ? 0 : externalCrlInfoData.hashCode());
        result = prime * result + ((cRLData == null) ? 0 : cRLData.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + (rootCA ? 1231 : 1237);
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((crlGenerationInfo == null) ? 0 : crlGenerationInfo.hashCode());
        result = prime * result + (publishToCDPS ? 1231 : 1237);
        result = prime * result + (isIssuerExternalCA ? 1231 : 1237);
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
        final CertificateAuthorityData other = (CertificateAuthorityData) obj;
        if (certificateDatas == null && other.certificateDatas != null) {
            return false;
        } else if (certificateDatas != null && other.certificateDatas == null) {
            return false;
        } else if (certificateDatas != null && certificateDatas.size() != other.certificateDatas.size()) {
            return false;
        } else if (certificateDatas != null && other.certificateDatas != null) {
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
        if (externalCrlInfoData == null) {
            if (other.externalCrlInfoData != null) {
                return false;
            }
        } else if (!externalCrlInfoData.equals(other.externalCrlInfoData)) {
            return false;
        }
        if (cRLData == null) {
            if (other.cRLData != null) {
                return false;
            }
        } else if (!cRLData.equals(other.cRLData)) {
            return false;
        }

        if (issuer == null) {
            if (other.issuer != null) {
                return false;
            }
        } else if (!issuer.equals(other.issuer)) {
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
        if (status == null) {
            if (other.status != null) {
                return false;
            }
        } else if (!status.equals(other.status)) {
            return false;
        }
        if (subjectAltName == null) {
            if (other.subjectAltName != null) {
                return false;
            }
        } else if (!subjectAltName.equals(other.subjectAltName)) {
            return false;
        }
        if (subjectDN == null) {
            if (other.subjectDN != null) {
                return false;
            }
        } else if (!subjectDN.equals(other.subjectDN)) {
            return false;
        }
        if (crlGenerationInfo == null) {
            if (other.crlGenerationInfo != null) {
                return false;
            }
        } else if (!crlGenerationInfo.equals(other.crlGenerationInfo)) {
            return false;
        }
        if (publishToCDPS != other.publishToCDPS) {
            return false;
        }
        if (isIssuerExternalCA != other.isIssuerExternalCA) {
            return false;
        }
        return true;
    }

}
