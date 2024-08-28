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
import java.util.Arrays;
import java.util.Date;

import javax.persistence.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;

@Entity
@Table(name = "certificate")
public class CertificateData implements Serializable {

    private static final long serialVersionUID = 1690191764030790232L;

    @Id
    @SequenceGenerator(name = "SEQ_CERTIFICATE_ID_GENERATOR", sequenceName = "SEQ_CERTIFICATE_ID", allocationSize = 1)
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "SEQ_CERTIFICATE_ID_GENERATOR")
    @Column(name = "id")
    private long id;

    @Column(name = "serial_number", nullable = false)
    private String serialNumber;

    @Column(name = "not_before", nullable = false)
    private Date notBefore;

    @Column(name = "not_after", nullable = false)
    private Date notAfter;

    @Column(name = "issued_time", nullable = false)
    private Date issuedTime;

    @Column(name = "certificate", nullable = false)
    private byte[] certificate;

    @Column(name = "status_id", nullable = false)
    private Integer status;

    @Column(name = "subject_dn", columnDefinition = "TEXT")
    private String subjectDN;

    @Column(name = "subject_alt_name", columnDefinition = "TEXT")
    private String subjectAltName;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "issuer_id")
    private CertificateAuthorityData issuerCA;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "key_id")
    private KeyIdentifierData keyIdentifier;

    @ManyToOne(fetch = FetchType.LAZY, cascade = { CascadeType.REFRESH })
    @JoinColumn(name = "issuer_certificate_id", nullable = true)
    private CertificateData issuerCertificate;

    @Column(name = "revoked_time", nullable = true)
    private Date revokedTime;

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
     * @return the serialNumber
     */
    public String getSerialNumber() {
        return serialNumber;
    }

    /**
     * @param serialNumber
     *            the serialNumber to set
     */
    public void setSerialNumber(final String serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * @return the notBefore
     */
    public Date getNotBefore() {
        return notBefore;
    }

    /**
     * @param notBefore
     *            the notBefore to set
     */
    public void setNotBefore(final Date notBefore) {
        this.notBefore = notBefore;
    }

    /**
     * @return the notAfter
     */
    public Date getNotAfter() {
        return notAfter;
    }

    /**
     * @param notAfter
     *            the notAfter to set
     */
    public void setNotAfter(final Date notAfter) {
        this.notAfter = notAfter;
    }

    /**
     * @return the issuedTime
     */
    public Date getIssuedTime() {
        return issuedTime;
    }

    /**
     * @param issuedTime
     *            the issuedTime to set
     */
    public void setIssuedTime(final Date issuedTime) {
        this.issuedTime = issuedTime;
    }

    /**
     * @return the certificate
     */
    public byte[] getCertificate() {
        return certificate;
    }

    /**
     * @param certificate
     *            the certificate to set
     */
    public void setCertificate(final byte[] certificate) {
        this.certificate = certificate;
    }

    /**
     * @return the Certificate Status
     */
    public CertificateStatus getStatus() {
        return CertificateStatus.getStatus(this.status);
    }

    /**
     * @param certificateStatus
     *            certificate status to be set.
     */
    public void setStatus(final CertificateStatus certificateStatus) {

        if (certificateStatus == null) {
            this.status = null;
        } else {
            this.status = certificateStatus.getId();
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
     * @return the issuerCertificate
     */
    public CertificateData getIssuerCertificate() {
        return issuerCertificate;
    }

    /**
     * @param issuerCertificate
     *            the issuerCertificate to set
     */
    public void setIssuerCertificate(final CertificateData issuerCertificate) {
        this.issuerCertificate = issuerCertificate;
    }

    /**
     * @return the keyIdentifier
     */
    public KeyIdentifierData getKeyIdentifier() {
        return keyIdentifier;
    }

    /**
     * @param keyIdentifier
     *            the keyIdentifier to set
     */
    public void setKeyIdentifier(final KeyIdentifierData keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    /**
     * @return the revokedTime
     */
    public Date getRevokedTime() {
        return revokedTime;
    }

    /**
     * @param revokedTime
     *            the revokedTime to set
     */
    public void setRevokedTime(final Date revokedTime) {
        this.revokedTime = revokedTime;
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
        result = prime * result + Arrays.hashCode(certificate);
        // result = prime * result + ((issuerCA == null) ? 0 : issuerCA.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((issuedTime == null) ? 0 : issuedTime.hashCode());
        result = prime * result + ((notAfter == null) ? 0 : notAfter.hashCode());
        result = prime * result + ((notBefore == null) ? 0 : notBefore.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subjectDN == null) ? 0 : subjectDN.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((keyIdentifier == null) ? 0 : keyIdentifier.hashCode());
        result = prime * result + ((revokedTime == null) ? 0 : revokedTime.hashCode());
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
        final CertificateData other = (CertificateData) obj;
        if (!Arrays.equals(this.getCertificate(), other.getCertificate())) {
            return false;
        }
        if (this.getIssuerCA() == null) {
            if (other.getIssuerCA() != null) {
                return false;
            }
        } else if (!this.getIssuerCA().equals(other.getIssuerCA())) {
            return false;
        }
        if (this.getKeyIdentifier() == null) {
            if (other.getKeyIdentifier() != null) {
                return false;
            }
        } else if (!this.getKeyIdentifier().equals(other.getKeyIdentifier())) {
            return false;
        }
        if (this.getId() != other.getId()) {
            return false;
        }
        if (this.getIssuedTime() == null) {
            if (other.getIssuedTime() != null) {
                return false;
            }
        } else if (!this.getIssuedTime().equals(other.getIssuedTime())) {
            return false;
        }
        if (this.getNotAfter() == null) {
            if (other.getNotAfter() != null) {
                return false;
            }
        } else if (!this.getNotAfter().equals(other.getNotAfter())) {
            return false;
        }
        if (this.getNotBefore() == null) {
            if (other.getNotBefore() != null) {
                return false;
            }
        } else if (!this.getNotBefore().equals(other.getNotBefore())) {
            return false;
        }
        if (this.getSerialNumber() == null) {
            if (other.getSerialNumber() != null) {
                return false;
            }
        } else if (!this.getSerialNumber().equals(other.getSerialNumber())) {
            return false;
        }
        if (this.getStatus() == null) {
            if (other.getStatus() != null) {
                return false;
            }
        } else if (!this.getStatus().equals(other.getStatus())) {
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
        if (this.getIssuerCertificate() == null) {
            if (other.getIssuerCertificate() != null) {
                return false;
            }
        } else if (!this.getIssuerCertificate().equals(other.getIssuerCertificate())) {
            return false;
        }
        if (this.getRevokedTime() == null) {
            if (other.getRevokedTime() != null) {
                return false;
            }
        } else if (!this.getRevokedTime().equals(other.getRevokedTime())) {
            return false;
        }

        return true;
    }

    /**
     * Returns string representation of {@link CertificateData} object.
     */
    @Override
    public String toString() {
        return "CertificateData [id=" + id + ", " + (null != serialNumber ? "serialNumber=" + serialNumber + ", " : "") + (null != notBefore ? "notBefore=" + notBefore + ", " : "")
                + (null != notAfter ? "notAfter=" + notAfter + ", " : "") + (null != issuedTime ? "issuedTime=" + issuedTime + ", " : "")
                + (null != certificate ? "certificate=" + Arrays.toString(certificate) + ", " : "") + (null != status ? "status=" + status : "")
                + (null != subjectDN ? "subjectDN=" + subjectDN + ", " : "") + (null != subjectAltName ? "subjectAltName=" + subjectAltName + ", " : "") + "]"
                + (null != subjectAltName ? "subjectAltName=" + subjectAltName + ", " : "") + (null != issuerCertificate ? "issuerCertificate=" + issuerCertificate + ", " : "")
                + (null != revokedTime ? "revokedDate=" + revokedTime + ", " : "") + "]";
    }

}
