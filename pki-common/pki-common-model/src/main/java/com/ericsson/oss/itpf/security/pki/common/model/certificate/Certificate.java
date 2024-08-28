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
package com.ericsson.oss.itpf.security.pki.common.model.certificate;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;

/**
 * Class containing all the attributes of a certificate like below.
 * 
 * <ul>
 * <li>Serial Number : Serial number of the certificate.</li>
 * <li>NotBefore : Time of the certificate generation.</li>
 * <li>NotAfter : Expire Time of the certificate.</li>
 * <li>IssuedTime : Actual Time of the certificate generation.</li>
 * <li>X509Certificate : X509Certificate Instance.</li>
 * <li>issuer : issuer of the certificate.</li>
 * <li>Status : Status of the certificate whether it is active, revoked or expired.</li>
 * <li>Subject : Subject dn of the certificate.</li>
 * <li>SubjectAltName : SAN extension of the certificate.</li>
 * <li>CertificateCategory : Enum for representing the certificate for which entity it belongs to.</li>
 * </ul>
 * This is used to represent the certificate data of end entity/ CA entity.
 * 
 */
@XmlRootElement(name = "Certificate")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Certificate", propOrder = { "id", "serialNumber", "notBefore", "notAfter", "issuedTime", "status", "issuer", "subject", "subjectAltName", "certificateCategory", "issuerCertificate",
        "revokedTime" })
public class Certificate implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -2905965255308007867L;

    @XmlAttribute(name = "Id")
    protected long id;

    @XmlElement(name = "SerialNumber")
    protected String serialNumber;

    @XmlElement(name = "NotBefore")
    protected Date notBefore;

    @XmlElement(name = "NotAfter")
    protected Date notAfter;

    @XmlElement(name = "IssuedTime")
    protected Date issuedTime;

    @XmlElement(name = "Status")
    protected CertificateStatus status;

    @XmlElement(name = "Issuer")
    protected CertificateAuthority issuer;

    @XmlTransient
    protected X509Certificate x509Certificate;

    @XmlElement(name = "Subject")
    protected Subject subject;

    @XmlElement(name = "SubjectAltName")
    protected SubjectAltName subjectAltName;

    @XmlElement(name = "CertificateCategory")
    protected CertificateCategory certificateCategory;

    @XmlElement(name = "issuerCertificate")
    protected Certificate issuerCertificate;

    @XmlElement(name = "RevokedTime")
    protected Date revokedTime;

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
     * @return the x509Certificate
     */
    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    /**
     * @param x509Certificate
     *            the x509Certificate to set
     */
    public void setX509Certificate(final X509Certificate x509Certificate) {
        this.x509Certificate = x509Certificate;
    }

    /**
     * @return the status
     */
    public CertificateStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final CertificateStatus status) {
        this.status = status;
    }

    /**
     * @return the issuerCA
     */
    public CertificateAuthority getIssuer() {
        return issuer;
    }

    /**
     * @param issuerCA
     *            the issuerCA to set
     */
    public void setIssuer(final CertificateAuthority issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the subject
     */
    public Subject getSubject() {
        return subject;
    }

    /**
     * @param subject
     *            the subject to set
     */
    public void setSubject(final Subject subject) {
        this.subject = subject;
    }

    /**
     * @return the subjectAltName
     */
    public SubjectAltName getSubjectAltName() {
        return subjectAltName;
    }

    /**
     * @param subjectAltName
     *            the subjectAltName to set
     */
    public void setSubjectAltName(final SubjectAltName subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    /**
     * @return the certificateCategory
     */
    public CertificateCategory getCertificateCategory() {
        return certificateCategory;
    }

    /**
     * @param certificateCategory
     *            the certificateCategory to set
     */
    public void setCertificateCategory(final CertificateCategory certificateCategory) {
        this.certificateCategory = certificateCategory;
    }

    /**
     * @return the issuerCertificate
     */
    public Certificate getIssuerCertificate() {
        return issuerCertificate;
    }

    /**
     * @param issuerCertificate
     *            the issuerCertificate to set
     */
    public void setIssuerCertificate(final Certificate issuerCertificate) {
        this.issuerCertificate = issuerCertificate;
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((issuedTime == null) ? 0 : issuedTime.hashCode());
        result = prime * result + ((notAfter == null) ? 0 : notAfter.hashCode());
        result = prime * result + ((notBefore == null) ? 0 : notBefore.hashCode());
        result = prime * result + ((serialNumber == null) ? 0 : serialNumber.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + ((x509Certificate == null) ? 0 : x509Certificate.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((certificateCategory == null) ? 0 : certificateCategory.hashCode());
        result = prime * result + ((issuerCertificate == null) ? 0 : issuerCertificate.hashCode());
        result = prime * result + ((revokedTime == null) ? 0 : revokedTime.hashCode());
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
        final Certificate other = (Certificate) obj;
        if (issuedTime == null) {
            if (other.issuedTime != null) {
                return false;
            }
        } else if (!issuedTime.equals(other.issuedTime)) {
            return false;
        }
        if (notAfter == null) {
            if (other.notAfter != null) {
                return false;
            }
        } else if (!notAfter.equals(other.notAfter)) {
            return false;
        }
        if (notBefore == null) {
            if (other.notBefore != null) {
                return false;
            }
        } else if (!notBefore.equals(other.notBefore)) {
            return false;
        }
        if (serialNumber == null) {
            if (other.serialNumber != null) {
                return false;
            }
        } else if (!serialNumber.equals(other.serialNumber)) {
            return false;
        }
        if (status != other.status) {
            return false;
        }
        if (issuer == null) {
            if (other.issuer != null) {
                return false;
            }
        } else if (!issuer.equals(other.issuer)) {
            return false;
        }
        if (x509Certificate == null) {
            if (other.x509Certificate != null) {
                return false;
            }
        } else if (!x509Certificate.equals(other.x509Certificate)) {
            return false;
        }
        if (subject == null) {
            if (other.subject != null) {
                return false;
            }
        } else if (!subject.equals(other.subject)) {
            return false;
        }
        if (subjectAltName == null) {
            if (other.subjectAltName != null) {
                return false;
            }
        } else if (!subjectAltName.equals(other.subjectAltName)) {
            return false;
        }
        if (certificateCategory != other.certificateCategory) {
            return false;
        }
        if (revokedTime == null) {
            if (other.revokedTime != null) {
                return false;
            }
        } else if (!revokedTime.equals(other.revokedTime)) {
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
        return "Certificate [id=" + id + ", " + (null != serialNumber ? "serialNumber=" + serialNumber + ", " : "") + (null != notBefore ? "notBefore=" + notBefore + ", " : "")
                + (null != notAfter ? "notAfter=" + notAfter + ", " : "") + (null != issuedTime ? "issuedTime=" + issuedTime + ", " : "")
                + (null != x509Certificate ? "x509Certificate=" + x509Certificate + ", " : "") + (null != status ? "status=" + status + ", " : "")
                + (null != issuer ? "issuerCA=" + issuer + ", " : "") + (null != subject ? "subject=" + subject + ", " : "")
                + (null != subjectAltName ? "subjectAltName=" + subjectAltName + ", " : "") + (null != certificateCategory ? "certificateCategory=" + certificateCategory + ", " : "")
                + (null != issuerCertificate ? "issuerCertificate=" + issuerCertificate + ", " : "") + (null != revokedTime ? "revokedDate=" + revokedTime + ", " : "") + "]";
    }
}
