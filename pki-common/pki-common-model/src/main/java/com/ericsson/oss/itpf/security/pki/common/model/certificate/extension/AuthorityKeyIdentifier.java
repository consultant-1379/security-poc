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

package com.ericsson.oss.itpf.security.pki.common.model.certificate.extension;

import java.io.Serializable;

import javax.xml.bind.annotation.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * The authority key identifier extension provides a means of identifying the public key corresponding to the private key used to sign a CRL. The identification can be based on either the key
 * identifier (the subject key identifier in the CRL signer's certificate) or the issuer name and serial number.
 * 
 * This class contains flags to whether use identify using key or combination of serial number and issuer.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="AuthorityKeyIdentifier">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;choice>
 *         &lt;element name="type" type="{}AuthorityKeyIdentifierType"/>
 *       &lt;/choice>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AuthorityKeyIdentifier", propOrder = { "type" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class AuthorityKeyIdentifier extends CertificateExtension implements Serializable {

    /**
         * 
         */
    private static final long serialVersionUID = 5865145675846427402L;

    @XmlElement(name = "AuthorityKeyIdentifierType", required = false)
    protected AuthorityKeyIdentifierType type;

    @XmlTransient
    protected SubjectKeyIdentifier subjectKeyIdentifier;

    @XmlTransient
    protected Certificate issuerSubjectAndSerialNumber;

    /**
     * @return the authorityKeyIdentifierType
     */
    public AuthorityKeyIdentifierType getType() {
        return type;
    }

    /**
     * @param authorityKeyIdentifierType
     *            the authorityKeyIdentifierType to set
     */
    public void setType(final AuthorityKeyIdentifierType authorityKeyIdentifierType) {
        this.type = authorityKeyIdentifierType;
    }

    /**
     * @return the subjectkeyIdentifier
     */
    public SubjectKeyIdentifier getSubjectkeyIdentifier() {
        return subjectKeyIdentifier;
    }

    /**
     * @param subjectkeyIdentifier
     *            the subjectkeyIdentifier to set
     */
    public void setSubjectkeyIdentifier(final SubjectKeyIdentifier subjectkeyIdentifier) {
        this.subjectKeyIdentifier = subjectkeyIdentifier;
    }

    /**
     * @return the issuerSubjectAndSerialNumber
     */
    public Certificate getIssuerSubjectAndSerialNumber() {
        return issuerSubjectAndSerialNumber;
    }

    /**
     * @param issuerSubjectAndSerialNumber
     *            the issuerSubjectAndSerialNumber to set
     */
    public void setIssuerSubjectAndSerialNumber(final Certificate issuerSubjectAndSerialNumber) {
        this.issuerSubjectAndSerialNumber = issuerSubjectAndSerialNumber;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "AuthorityKeyIdentifier [authorityKeyIdentifierType=" + type + ", subjectkeyIdentifier=" + subjectKeyIdentifier + ", issuerSubjectAndSerialNumber=" + issuerSubjectAndSerialNumber + "]";
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = super.hashCode();
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((subjectKeyIdentifier == null) ? 0 : subjectKeyIdentifier.hashCode());
        result = prime * result + ((issuerSubjectAndSerialNumber == null) ? 0 : issuerSubjectAndSerialNumber.hashCode());
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
        if (!super.equals(obj)) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AuthorityKeyIdentifier other = (AuthorityKeyIdentifier) obj;
        if (type != other.type) {
            return false;
        }
        if (subjectKeyIdentifier == null) {
            if (other.subjectKeyIdentifier != null) {
                return false;
            }
        } else if (!subjectKeyIdentifier.equals(other.subjectKeyIdentifier)) {
            return false;
        }
        if (issuerSubjectAndSerialNumber == null) {
            if (other.issuerSubjectAndSerialNumber != null) {
                return false;
            }
        } else if (!issuerSubjectAndSerialNumber.equals(other.issuerSubjectAndSerialNumber)) {
            return false;
        }
        return true;
    }
}
