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

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;

@Entity
@Table(name = "entity_info")
public class EntityInfoData implements Serializable {

    private static final long serialVersionUID = 1L;

    @Id
    private long id;

    @Column(name = "Name", nullable = false, unique = true)
    private String name;

    @Column(name = "otp")
    private String otp;

    @Column(name = "otp_count")
    private Integer otpCount;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @Column(name = "subject_dn", columnDefinition = "TEXT")
    private String subjectDN;

    @Column(name = "subject_alt_name", columnDefinition = "TEXT")
    private String subjectAltName;

    @OneToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "issuer_id")
    private CertificateAuthorityData issuerCA;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinTable(name = "ENTITY_CERTIFICATE", joinColumns = @JoinColumn(name = "entity_id"), inverseJoinColumns = @JoinColumn(name = "certificate_id"))
    private Set<CertificateData> certificateDatas = new HashSet<>();

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;

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
     * @return the oTP
     */
    public String getoTP() {
        return otp;
    }

    /**
     * @param oTP
     *            the oTP to set
     */
    public void setoTP(final String oTP) {
        this.otp = oTP;
    }

    /**
     * @return the oTPCount
     */
    public Integer getoTPCount() {
        return otpCount;
    }

    /**
     * @param oTPCount
     *            the oTPCount to set
     */
    public void setoTPCount(final Integer oTPCount) {
        this.otpCount = oTPCount;
    }

    /**
     * @return the Entity Status
     */
    public EntityStatus getStatus() {
        return EntityStatus.getStatus(this.status);
    }

    /**
     * @param entityStatus
     *            entity status to be set.
     */
    public void setStatus(final EntityStatus entityStatus) {

        if (entityStatus == null) {
            this.status = null;
        } else {
            this.status = entityStatus.getId();
        }
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
        // result = prime * result + ((certificateDatas == null) ? 0 : certificateDatas.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((issuerCA == null) ? 0 : issuerCA.hashCode());
        result = prime * result + ((otp == null) ? 0 : otp.hashCode());
        result = prime * result + ((otpCount == null) ? 0 : (int) (otpCount ^ (otpCount >>> 32)));
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
        final EntityInfoData other = (EntityInfoData) obj;
        if (this.getCertificateDatas() == null) {
            if (other.getCertificateDatas() != null) {
                return false;
            }
        } else if (this.getCertificateDatas() != null && other.getCertificateDatas() == null) {
            return false;
        } else if (this.getCertificateDatas() != null && other.getCertificateDatas() != null) {
            if (this.getCertificateDatas().size() != other.getCertificateDatas().size()) {
                return false;
            }
            boolean isMatched = false;
            for (final CertificateData certificateData : this.getCertificateDatas()) {
                for (final CertificateData certificateDataOther : other.getCertificateDatas()) {
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
        if (this.getId() != other.getId()) {
            return false;
        }
        if (this.getName() == null) {
            if (other.getName() != null) {
                return false;
            }
        } else if (!this.getName().equals(other.getName())) {
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
        if (this.getoTP() == null) {
            if (other.getoTP() != null) {
                return false;
            }
        } else if (!this.getoTP().equals(other.getoTP())) {
            return false;
        }
        if (this.getoTPCount() == null) {
            if (other.getoTPCount() != null) {
                return false;
            }
        } else if (!this.getoTPCount().equals(other.getoTPCount())) {
            return false;
        }
        if (!status.equals(other.status)) {
            return false;
        }
        if (issuerCA == null) {
            if (other.issuerCA != null) {
                return false;
            }
        } else if (!issuerCA.equals(other.issuerCA)) {
            return false;
        }
        return true;
    }

    /**
     * Returns string representation of {@link EntityInfoData} object.
     */
    @Override
    public String toString() {
        return "EntityInfoData [id=" + id + ", " + (null != name ? "name=" + name + ", " : "") + (null != otp ? "name=" + name + ", " : "") + "otpCount=" + otpCount + ", "
                + (null != subjectDN ? "subjectDN=" + subjectDN + ", " : "") + (null != subjectAltName ? "subjectAltName=" + subjectAltName + ", " : "") + "status=" + status + ", "
                + (null != issuerCA ? "issuerCA=" + issuerCA : "") + "]";
    }

}
