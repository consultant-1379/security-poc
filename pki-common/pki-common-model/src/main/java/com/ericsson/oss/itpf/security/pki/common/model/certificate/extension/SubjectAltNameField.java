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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;

/**
 * <p>
 * This class is contains the type of subject Alternative name and list of values for that type.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * 
 * <pre>
 * &lt;complexType name="SubjectAltNameField">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="Type" type="{}SubjectAltNameFieldType"/>
 *         &lt;element name="Value" type="{}AbstractSubjectAltNameFieldValue" minOccurs="1"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SubjectAltNameField", propOrder = { "type", "value" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class SubjectAltNameField implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -7038626322300662302L;
    @XmlElement(name = "Type", required = true)
    protected SubjectAltNameFieldType type;
    @XmlElement(name = "Value", required = true)
    protected AbstractSubjectAltNameFieldValue value;

    /**
     * @return the type
     */
    public SubjectAltNameFieldType getType() {
        return type;
    }

    /**
     * @param type
     *            the type to set
     */
    public void setType(final SubjectAltNameFieldType type) {
        this.type = type;
    }

    /**
     * @return the value
     */
    public AbstractSubjectAltNameFieldValue getValue() {
        return value;
    }

    /**
     * @param value
     *            the value to set
     */
    public void setValue(final AbstractSubjectAltNameFieldValue value) {
        this.value = value;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " [Type: " + type + " ,Value: " + value + "] ";
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
        result = prime * result + ((type == null) ? 0 : type.hashCode());
        result = prime * result + ((value == null) ? 0 : value.hashCode());
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
        final SubjectAltNameField other = (SubjectAltNameField) obj;
        if (!type.equals(other.type)) {
            return false;
        }
        if (!value.equals(other.value)) {
            return false;
        }
        return true;
    }
}
