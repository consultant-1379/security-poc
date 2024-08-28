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
package com.ericsson.oss.itpf.security.pki.common.model;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;

/**
 * This class holds the information of certificate authority. This is used in PKI Core and PKI Manager.
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateAuthority">
 *   &lt;complexContent>
 *    &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *          &lt;element name="Id" type="xs:positiveInteger" minOccurs="0" />
 *          &lt;element name="Name" type="nonEmptyString" minOccurs="0" />
 *          &lt;element name="IsRootCA" type="xs:boolean" minOccurs="0" />
 *          &lt;element name="Subject" type="Subject" minOccurs="0" />
 *          &lt;element name="SubjectAltName" type="SubjectAltName" minOccurs="0" />
 *          &lt;element name="Issuer" type="CertificateAuthority" minOccurs="0" />
 *          &lt;element name="status" type="CAStatus" minOccurs="0" />
 *          &lt;element name="crlGenerationInfo" type="CrlGenerationInfo" minOccurs="0" maxOccurs=unbounded/>
 *          &lt;element name="publishToCDPS" type="xs:boolean" minOccurs="0" />
 *          &lt;element name="isIssuerExternalCA" type="xs:boolean" minOccurs="0" />
 *       &lt;/sequence>
 *    &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "CertificateAuthority")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateAuthority", propOrder = { "id", "name", "isRootCA", "subject", "subjectAltName", "issuer", "activeCertificate", "inActiveCertificates", "status", "crlGenerationInfo",
        "publishToCDPS", "isIssuerExternalCA" })
public class CertificateAuthority implements Serializable {
    private static final long serialVersionUID = -2097786196924540286L;
    @XmlElement(name = "Id", required = false)
    @XmlSchemaType(name = "positiveInteger")
    protected long id;
    @XmlElement(name = "Name", required = true)
    protected String name;
    @XmlElement(name = "IsRootCA")
    protected boolean isRootCA;
    @XmlElement(name = "Subject")
    protected Subject subject;
    @XmlElement(name = "SubjectAltName")
    protected SubjectAltName subjectAltName;
    @XmlElement(name = "Issuer")
    protected CertificateAuthority issuer;
    @XmlElement(name = "InActiveCertificates")
    protected List<Certificate> inActiveCertificates = new ArrayList<Certificate>();
    @XmlElement(name = "ActiveCertificate")
    protected Certificate activeCertificate;
    @XmlElement(name = "CAStatus")
    protected CAStatus status;
    @XmlTransient
    protected List<CRLInfo> crlInfo;
    @XmlElement(name = "CrlGenerationInfo", required = false)
    protected List<CrlGenerationInfo> crlGenerationInfo;
    @XmlElement(name = "PublishToCDPS", required = false)
    protected boolean publishToCDPS;
    @XmlElement(name = "IsIssuerExternalCA", required = false)
    protected boolean isIssuerExternalCA;

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
     */
    public CertificateAuthority() {
        this.status = CAStatus.NEW;
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
     * @return the isRootCA
     */
    public boolean isRootCA() {
        return isRootCA;
    }

    /**
     * @param isRootCA
     *            the isRootCA to set
     */
    public void setRootCA(final boolean isRootCA) {
        this.isRootCA = isRootCA;
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
     * @return the issuer
     */
    public CertificateAuthority getIssuer() {
        return issuer;
    }

    /**
     * @param issuer
     *            the issuer to set
     */
    public void setIssuer(final CertificateAuthority issuer) {
        this.issuer = issuer;
    }

    /**
     * @return the inActiveCertificates
     */
    public List<Certificate> getInActiveCertificates() {
        return inActiveCertificates;
    }

    /**
     * @param inActiveCertificates
     *            the inActiveCertificates to set
     */
    public void setInActiveCertificates(final List<Certificate> inActiveCertificates) {
        this.inActiveCertificates = inActiveCertificates;
    }

    /**
     * @return the activeCertificate
     */
    public Certificate getActiveCertificate() {
        return activeCertificate;
    }

    /**
     * @param activeCertificate
     *            the activeCertificate to set
     */
    public void setActiveCertificate(final Certificate activeCertificate) {
        this.activeCertificate = activeCertificate;
    }

    /**
     * @return the status
     */
    public CAStatus getStatus() {
        return status;
    }

    /**
     * @param status
     *            the status to set
     */
    public void setStatus(final CAStatus status) {
        this.status = status;
    }

    /**
     * @return the crlInfo
     */
    public List<CRLInfo> getCrlInfo() {
        return crlInfo;
    }

    /**
     * @param crlInfo
     *            the crlInfo to set
     */
    public void setCrlInfo(final List<CRLInfo> crlInfo) {
        this.crlInfo = crlInfo;
    }

    /**
     * @return the crlGenerationInfo
     */
    public List<CrlGenerationInfo> getCrlGenerationInfo() {
        return crlGenerationInfo;
    }

    /**
     * @param crlGenerationInfo
     *            the crlGenerationInfo to set
     */
    public void setCrlGenerationInfo(final List<CrlGenerationInfo> crlGenerationInfo) {
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
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((activeCertificate == null) ? 0 : activeCertificate.hashCode());
        result = prime * result + ((crlGenerationInfo == null) ? 0 : crlGenerationInfo.hashCode());
        result = prime * result + ((crlInfo == null) ? 0 : crlInfo.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((inActiveCertificates == null) ? 0 : inActiveCertificates.hashCode());
        result = prime * result + (isRootCA ? 1231 : 1237);
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + (publishToCDPS ? 1231 : 1237);
        result = prime * result + (isIssuerExternalCA ? 1231 : 1237);
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        return result;
    }

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
        final CertificateAuthority other = (CertificateAuthority) obj;
        if (activeCertificate == null) {
            if (other.activeCertificate != null) {
                return false;
            }
        } else if (!activeCertificate.equals(other.activeCertificate)) {
            return false;
        }
        if (crlGenerationInfo == null) {
            if (other.crlGenerationInfo != null) {
                return false;
            }
        } else if (!crlGenerationInfo.equals(other.crlGenerationInfo)) {
            return false;
        }
        if (crlInfo == null) {
            if (other.crlInfo != null) {
                return false;
            }
        } else if (!crlInfo.equals(other.crlInfo)) {
            return false;
        }
        if (id != other.id) {
            return false;
        }
        if (inActiveCertificates == null) {
            if (other.inActiveCertificates != null) {
                return false;
            }
        } else if (!inActiveCertificates.equals(other.inActiveCertificates)) {
            return false;
        }
        if (isRootCA != other.isRootCA) {
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
        if (publishToCDPS != other.publishToCDPS) {
            return false;
        }
        if (isIssuerExternalCA != other.isIssuerExternalCA) {
            return false;
        }
        if (status != other.status) {
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
        return true;
    }

    @Override
    public String toString() {
        return "CertificateAuthority [id=" + id + ", name=" + name + ", isRootCA=" + isRootCA + ", subject=" + subject + ", subjectAltName=" + subjectAltName + ", issuer=" + issuer
                + ", inActiveCertificates=" + inActiveCertificates + ", activeCertificate=" + activeCertificate + ", status=" + status + ", crlInfo=" + crlInfo + ", crlGenerationInfo="
                + crlGenerationInfo + ", publishToCDPS=" + publishToCDPS + ", isIssuerExternalCA=" + isIssuerExternalCA + "]";
    }

}
