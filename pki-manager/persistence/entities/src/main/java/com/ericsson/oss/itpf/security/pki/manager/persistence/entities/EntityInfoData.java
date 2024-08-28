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
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;

@Embeddable
public class EntityInfoData implements Serializable {

    private static final long serialVersionUID = 1L;

    @Column(name = "Name", nullable = false, unique = true)
    private String name;

    @Column(nullable = true)
    private String otp;

    @Column(name = "otp_count", nullable = true)
    private int otpCount;

    @Column(name = "subject_dn", nullable = true, columnDefinition = "TEXT")
    private String subjectDN;

    @Column(name = "subject_alt_name", nullable = true, columnDefinition = "TEXT")
    private String subjectAltName;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "issuer_id", nullable = true)
    private CAEntityData issuer;

    @OneToMany(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH, CascadeType.MERGE, CascadeType.PERSIST })
    @JoinTable(name = "ENTITY_CERTIFICATE", joinColumns = @JoinColumn(name = "entity_id"), inverseJoinColumns = @JoinColumn(name = "certificate_id"))
    private Set<CertificateData> certificateDatas = new HashSet<CertificateData>();

    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "created_date", nullable = false, updatable = false)
    private Date createdDate;
    
    @Temporal(TemporalType.TIMESTAMP)
    @Column(name = "modified_date", nullable = false)
    private Date modifiedDate;

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

    /**
     * @param createdDate
     */
    public void setCreatedDate(final Date createdDate) {
        this.createdDate = createdDate;
    }

    /**
     * @param modifiedDate
     */
    public void setModifiedDate(final Date modifiedDate) {
        this.modifiedDate = modifiedDate;
    }

    public EntityStatus getStatus() {
        return EntityStatus.getStatus(this.status);
    }

    public void setStatus(final EntityStatus entityStatus) {

        if (entityStatus == null) {
            this.status = null;
        } else {
            this.status = entityStatus.getId();
        }
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
     * @return the otp
     */
    public String getOtp() {
        return otp;
    }

    /**
     * @param otp
     *            the otp to set
     */
    public void setOtp(final String otp) {
        this.otp = otp;
    }

    /**
     * @return the otpCount
     */
    public int getOtpCount() {
        return otpCount;
    }

    /**
     * @param otpCount
     *            the otpCount to set
     */
    public void setOtpCount(final int otpCount) {
        this.otpCount = otpCount;
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
     * @return the issuer
     */
    public CAEntityData getIssuer() {
        return issuer;
    }

    /**
     * @param issuer
     *            the issuer to set
     */
    public void setIssuer(final CAEntityData issuer) {
        this.issuer = issuer;
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "EntityInfoData [" + (name != null ? "name=" + name + ", " : "") + (otp != null ? "otp=" + otp + ", " : "") + "otpCount=" + otpCount + ", "
                + (subjectDN != null ? "subjectDN=" + subjectDN + ", " : "") + (subjectAltName != null ? "subjectAltName=" + subjectAltName + ", " : "")
                + (status != null ? "status=" + status + ", " : "") + (issuer != null ? "issuer=" + issuer + ", " : "") + (certificateDatas != null ? "certificateDatas=" + certificateDatas : "")
                + "]";
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
        result = prime * result + ((certificateDatas == null) ? 0 : certificateDatas.hashCode());
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((otp == null) ? 0 : otp.hashCode());
        result = prime * result + otpCount;
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
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
        final EntityInfoData other = (EntityInfoData) obj;
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
        if (otp == null) {
            if (other.otp != null) {
                return false;
            }
        } else if (!otp.equals(other.otp)) {
            return false;
        }
        if (otpCount != other.otpCount) {
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
        return true;
    }

}
