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
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.*;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * This is wrapper class for list of Subject Alternative name values.
 * 
 * <p>
 * The subject alternative name extension allows identities to be bound to the subject of the certificate. If the subject field contains an empty sequence, then the issuing CA MUST include a
 * subjectAltName extension that is marked as critical. When including the subjectAltName extension in a certificate that has a non-empty subject distinguished name, conforming CAs SHOULD mark the
 * subjectAltName extension as non-critical. USer should be allow to choose one or more values from supported values. For example, certificate profile can have two Directory name and three DNS Name
 * This certificate extension template holds the supported subject alternative name types.
 * 
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * 
 * <pre>
 * &lt;complexType name="SubjectAltName">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="SubjectAltNameField" type="{}SubjectAltNameField" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SubjectAltName", propOrder = { "subjectAltNameFields" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class SubjectAltName extends CertificateExtension implements Serializable {
    /**
         * 
         */
    private static final long serialVersionUID = -9022387876184045149L;

    @XmlElement(name = "SubjectAltNameField", required = true)
    protected List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

    /**
     * @return the subjectAltNameValue
     */
    public List<SubjectAltNameField> getSubjectAltNameFields() {
        return subjectAltNameFields;
    }

    /**
     * @param subjectAltNameValue
     *            the subjectAltNameValue to set
     */
    public void setSubjectAltNameFields(final List<SubjectAltNameField> subjectAltNameFields) {
        this.subjectAltNameFields = subjectAltNameFields;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {

        if (subjectAltNameFields != null) {
            return subjectAltNameFields.toString();
        } else {
            return "";
        }
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
        result = prime * result + ((subjectAltNameFields == null) ? 0 : subjectAltNameFields.hashCode());
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
        final SubjectAltName other = (SubjectAltName) obj;
        if (subjectAltNameFields == null) {
            if (other.subjectAltNameFields != null) {
                return false;
            }
        } else if (other.subjectAltNameFields == null) {
            if (subjectAltNameFields != null) {
                return false;
            }

        } else if (subjectAltNameFields != null && other.subjectAltNameFields != null) {
            if (subjectAltNameFields.size() != other.subjectAltNameFields.size()) {
                return false;
            }

            boolean isMatched = false;
            for (final SubjectAltNameField subjectAltNameField : subjectAltNameFields) {
                for (final SubjectAltNameField subjectAltNameFieldOther : other.subjectAltNameFields) {
                    if (subjectAltNameField.equals(subjectAltNameFieldOther)) {
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
        return true;
    }
}
