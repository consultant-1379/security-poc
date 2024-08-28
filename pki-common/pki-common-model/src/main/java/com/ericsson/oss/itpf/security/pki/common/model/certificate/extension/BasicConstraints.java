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
 * The basic constraints extension identifies whether the subject of the certificate is a CA and the maximum depth of valid certification paths that include this certificate.
 * 
 * This class contains attributes to enable this extension and give various properties like isCA and path length for that CA.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * 
 * <pre>
 * &lt;complexType name="BasicConstraints">
 *   &lt;complexContent>
 *     &lt;extension base="{}CertificateExtension">
 *       &lt;sequence>
 *         &lt;element name="IsCA" type="{http://www.w3.org/2001/XMLSchema}boolean"/>
 *         &lt;element name="PathLenConstraint" type="{http://www.w3.org/2001/XMLSchema}positiveInteger" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "BasicConstraints", propOrder = { "isCA", "pathLenConstraint" })
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE, setterVisibility = Visibility.NONE, isGetterVisibility = Visibility.NONE, creatorVisibility = Visibility.NONE)
public class BasicConstraints extends CertificateExtension implements Serializable {

    /**
         * 
         */
    private static final long serialVersionUID = -9162100827695821256L;

    @XmlElement(name = "IsCA", required = true)
    protected boolean isCA;
    @XmlElement(name = "PathLenConstraint", required = false)
    @XmlSchemaType(name = "positiveInteger")
    protected Integer pathLenConstraint;

    /**
     * Gets the value of the ca property.
     * 
     */
    public boolean isCA() {
        return isCA;
    }

    /**
     * Sets the value of the ca property.
     * 
     */
    public void setIsCA(final boolean value) {
        this.isCA = value;
    }

    /**
     * Gets the value of the pathLenConstraint property.
     * 
     * @return The pathLenConstriant value.
     * 
     */
    public Integer getPathLenConstraint() {
        return pathLenConstraint;
    }

    /**
     * Sets the value of the pathLenConstraint property.
     * 
     * @param value
     *            The pathLenConstriant value to set.
     * 
     */
    public void setPathLenConstraint(final Integer value) {
        this.pathLenConstraint = value;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return " Basic COnstraints: [ isCritical: " + critical + " isCA: " + isCA + " pathLenConstraint: " + pathLenConstraint + " ] ";
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
        result = prime * result + (isCA ? 1231 : 1237);
        result = prime * result + ((pathLenConstraint == null) ? 0 : pathLenConstraint);
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
        final BasicConstraints other = (BasicConstraints) obj;
        if (isCA != other.isCA) {
            return false;
        }
        if (pathLenConstraint == null) {
            if (other.pathLenConstraint != null) {
                return false;
            }
        } else if (!pathLenConstraint.equals(other.pathLenConstraint)) {
            return false;
        }
        return true;
    }
}
