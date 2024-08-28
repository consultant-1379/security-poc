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

import org.bouncycastle.asn1.x500.*;

/**
 * <p>
 * This contains the list of subject fields. toString method gives a ASN1 String of Subject.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class
 * 
 * <pre>
 * &lt;complexType name="Subject">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *          &lt;element name="SubjectField" type="{}SubjectField" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "Subject", propOrder = { "subjectFields" })
public class Subject implements Serializable {

    private static final long serialVersionUID = -1178096039289556276L;

    @XmlElement(required = false, name = "SubjectField")
    protected List<SubjectField> subjectFields = new ArrayList<SubjectField>();

    /**
     * @return the subjectFields
     */
    public List<SubjectField> getSubjectFields() {
        return subjectFields;
    }

    /**
     * @param subjectFields
     *            the subjectFields to set
     */
    public void setSubjectFields(final List<SubjectField> subjectFields) {
        this.subjectFields = subjectFields;
    }

    /**
     * This method provides a feature of converting a ASN1String like "C=AU, ST=Victoria" to Subject Object.
     *
     * @param distinguishedName
     * @return Object of Subject class with map containing values from given ASN1 String.
     */
    public Subject fromASN1String(final String distinguishedName) {
        String attributeValue = "";
        if (distinguishedName == null || distinguishedName.isEmpty()) {
            return this;
        } else {
            final X500Name x500Name = new X500Name(distinguishedName);
            final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

            for (final RDN rdn : x500Name.getRDNs()) {
                for (final AttributeTypeAndValue attributeTypeAndValue : rdn.getTypesAndValues()) {
                    final SubjectField subjectField = new SubjectField();
                    subjectField.setType(SubjectFieldType.fromOID(attributeTypeAndValue.getType().toString()));
                    attributeValue = attributeTypeAndValue.getValue().toString();

                    subjectField.setValue(attributeValue);
                    subjectFields.add(subjectField);
                }
            }
            this.subjectFields = subjectFields;
            return this;
        }
    }

    /**
     * This method provides a feature of converting a Subject Object to ASN1String like "C=AU, ST=Victoria".
     *
     * @see java.lang.Object#toString()
     * @return distinguishedName
     */
    public String toASN1String() {
        String subjectDNString = "";
        StringBuilder strBuilder = new StringBuilder();

        for (final SubjectField subjectField : subjectFields) {
            if (subjectField.getValue() != null && subjectField.getValue().contains(",") && !subjectField.getValue().contains("\\,")) {
                strBuilder = strBuilder.append(subjectField.getType().getValue() + "=" +  subjectField.getValue().replace("," , "\\,") + ",");
            } else {
                strBuilder = strBuilder.append(subjectField.getType().getValue() + "=" + subjectField.getValue() + ",");
            }
        }

        subjectDNString = strBuilder.toString();

        if (!subjectDNString.isEmpty()) {
            return subjectDNString.substring(0, subjectDNString.length() - 1);
        } else {
            return subjectDNString;
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
        result = prime * result + ((subjectFields == null) ? 0 : subjectFields.hashCode());
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
        final Subject other = (Subject) obj;
        if (subjectFields == null) {
            if (other.subjectFields != null) {
                return false;
            }
        } else if (subjectFields.size() != other.subjectFields.size()) {
            return false;
        } else if (subjectFields != null && other.subjectFields != null) {
            boolean subjectFieldFound = false;
            for (final SubjectField subjectField : subjectFields) {
                for (final SubjectField subjectFieldOther : other.subjectFields) {
                    if (subjectField.getType().equals(subjectFieldOther.getType()) && subjectField.getValue().equals(subjectFieldOther.getValue())) {
                        subjectFieldFound = true;
                        break;
                    } else {
                        subjectFieldFound = false;
                    }
                }
                if (!subjectFieldFound) {
                    return false;
                }
                subjectFieldFound = false;
            }
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
        return "Subject [" + (null != subjectFields ? "subjectFields=" + subjectFields + ", " : "") + "]";
    }
}

