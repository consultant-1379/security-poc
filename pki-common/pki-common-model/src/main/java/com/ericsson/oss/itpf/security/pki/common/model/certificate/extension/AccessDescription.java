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
 * This class contains access method and its respective access location as per RFC5280 ASN1 Structure.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="AccessDescription">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="AccessMethod" type="{}AccessMethods"/>
 *         &lt;element name="AccessLocation" type="{}nonEmptyString" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AccessDescription", propOrder = { "accessMethod", "accessLocation" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class AccessDescription implements Serializable {

    /**
	 * 
	 */
    private static final long serialVersionUID = -8003850279331944065L;
    @XmlElement(name = "AccessMethod", required = true)
    protected AccessMethod accessMethod;
    @XmlElement(name = "AccessLocation", required = false)
    protected String accessLocation;

    /**
     * @return the accessMethod
     */
    public AccessMethod getAccessMethod() {
        return accessMethod;
    }

    /**
     * @param accessMethod
     *            the accessMethod to set
     */
    public void setAccessMethod(final AccessMethod accessMethod) {
        this.accessMethod = accessMethod;
    }

    /**
     * @return the accessLocation
     */
    public String getAccessLocation() {
        return accessLocation;
    }

    /**
     * @param accessLocation
     *            the accessLocation to set
     */
    public void setAccessLocation(final String accessLocation) {
        this.accessLocation = accessLocation;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " Access Description: [ AccessMethod: " + accessMethod + ((null == accessLocation) ? "" : (" AccessLocation: " + accessLocation)) + " ] ";
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
        result = prime * result + ((accessLocation == null) ? 0 : accessLocation.hashCode());
        result = prime * result + ((accessMethod == null) ? 0 : accessMethod.hashCode());
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
        final AccessDescription other = (AccessDescription) obj;
        if (accessLocation == null) {
            if (other.accessLocation != null) {
                return false;
            }
        } else if (!accessLocation.equals(other.accessLocation)) {
            return false;
        }
        if (accessMethod != other.accessMethod) {
            return false;
        }
        return true;
    }

}
