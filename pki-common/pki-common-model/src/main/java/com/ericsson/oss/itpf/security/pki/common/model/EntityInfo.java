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

/**
 * This class holds the information of entity. This is used in PKI Core and PKI Manager.
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="EntityInfo">
 *   &lt;complexContent>
 *    &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *          &lt;element name="Id" type="xs:positiveInteger" minOccurs="0" />
 *          &lt;element name="Name" type="nonEmptyString" minOccurs="0" />
 *          &lt;element name="Subject" type="Subject" minOccurs="0" />
 *          &lt;element name="SubjectAltName" type="SubjectAltName" minOccurs="0" />
 *          &lt;element name="OTP" type="{}nonEmptyString" minOccurs="0" />
 *          &lt;element name="OTPCount" type="xs:positiveInteger" minOccurs="0" />
 *          &lt;element name="Issuer" type="CertificateAuthority" minOccurs="0" />
 *       &lt;/sequence>
 *    &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement(name = "EntityInfo")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EntityInfo", propOrder = { "id", "name", "subject", "subjectAltName", "oTP", "oTPCount", "issuer", "activeCertificate", "inActiveCertificates", "status" })
public class EntityInfo implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -1305655501908194381L;
    @XmlTransient
    private static final int DEFAULT_OTP_COUNT = 5;
    @XmlElement(name = "Id", required = false)
    @XmlSchemaType(name = "positiveInteger")
    protected long id;
    @XmlElement(name = "Name", required = true)
    protected String name;
    @XmlElement(name = "OTP", required = false)
    private String oTP;
    @XmlElement(name = "OTPCount", required = false)
    private int oTPCount;
    @XmlElement(name = "Status")
    protected EntityStatus status;
    @XmlElement(name = "Issuer", required = true)
    protected CertificateAuthority issuer;
    @XmlElement(name = "Subject")
    protected Subject subject;
    @XmlElement(name = "SubjectAltName")
    protected SubjectAltName subjectAltName;
    @XmlElement(name = "ActiveCertificate")
    protected Certificate activeCertificate;
    @XmlElement(name = "InActiveCertificates")
    protected List<Certificate> inActiveCertificates = new ArrayList<Certificate>();

    /**
     * 
     */
    public EntityInfo() {
        this.status = EntityStatus.NEW;
        this.oTPCount = DEFAULT_OTP_COUNT;
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
     * @return the entityStatus
     */
    public EntityStatus getStatus() {
        return status;
    }

    /**
     * @param entityStatus
     *            the entityStatus to set
     */
    public void setStatus(final EntityStatus status) {
        this.status = status;
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
     * @return the oTP
     */
    public String getOTP() {
        return oTP;
    }

    /**
     * @param oTP
     *            the oTP to set
     */
    public void setOTP(final String oTP) {
        this.oTP = oTP;
    }

    /**
     * @return the oTPCount
     */
    public int getOTPCount() {
        return oTPCount;
    }

    /**
     * @param oTPCount
     *            the oTPCount to set
     */
    public void setOTPCount(final int oTPCount) {
        this.oTPCount = oTPCount;
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

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "EntityInfo [id=" + id + ", " + (name != null ? "name=" + name + ", " : "") + (status != null ? "status=" + status + ", " : "") 
        		+ (issuer != null ? "issuer=" + issuer + ", " : "") + (subject != null ? "subject=" + subject + ", " : "")
        		+ (subjectAltName != null ? "subjectAltName="+ subjectAltName + ", " : "") + (activeCertificate != null ? "activeCertificate=" + activeCertificate + ", " : "")
                + (inActiveCertificates != null ? "inActiveCertificates=" + inActiveCertificates + ", " : "") + "]";
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
        result = prime * result + ((activeCertificate == null) ? 0 : activeCertificate.hashCode());
        result = prime * result + (int) (id ^ (id >>> 32));
        result = prime * result + ((inActiveCertificates == null) ? 0 : inActiveCertificates.hashCode());
        result = prime * result + ((name == null) ? 0 : name.hashCode());
        result = prime * result + ((subject == null) ? 0 : subject.hashCode());
        result = prime * result + ((subjectAltName == null) ? 0 : subjectAltName.hashCode());
        result = prime * result + ((oTP == null) ? 0 : oTP.hashCode());
        result = prime * result + oTPCount;
        result = prime * result + ((issuer == null) ? 0 : issuer.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
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
        final EntityInfo other = (EntityInfo) obj;
        if (activeCertificate == null) {
            if (other.activeCertificate != null) {
                return false;
            }
        } else if (!activeCertificate.equals(other.activeCertificate)) {
            return false;
        }

        if (inActiveCertificates == null) {
            if (other.inActiveCertificates != null) {
                return false;
            }
        } else if (inActiveCertificates != null && other.inActiveCertificates != null) {
            if (inActiveCertificates.size() != other.inActiveCertificates.size()) {
                return false;
            }
            boolean isMatched = false;
            for (final Certificate certificate : inActiveCertificates) {
                for (final Certificate certificateOther : other.inActiveCertificates) {
                    if (certificate.equals(certificateOther)) {
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
        if (name == null) {
            if (other.name != null) {
                return false;
            }
        } else if (!name.equals(other.name)) {
            return false;
        }
        if (oTPCount != other.oTPCount) {
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
        if (issuer == null) {
            if (other.issuer != null) {
                return false;
            }
        } else if (!issuer.equals(other.issuer)) {
            return false;
        }
        if (status != other.status) {
            return false;
        }
        return true;
    }

}
