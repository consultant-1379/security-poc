//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.7 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2014.11.25 at 11:38:50 AM GMT 
//

package com.ericsson.oss.itpf.security.credmsapi.api.model;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * Java class for CertificateExtensionType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="CertificateExtensionType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="subjectalternativename" type="{}SubjectAlternativeNameType" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CertificateExtensionType", propOrder = { "subjectalternativename" })
public class CertificateExtensionType {

    protected SubjectAlternativeNameType subjectalternativename;

    /**
     * Gets the value of the subjectalternativename property.
     * 
     * @return possible object is {@link SubjectAlternativeNameType }
     * 
     */
    public SubjectAlternativeNameType getSubjectalternativename() {
        return subjectalternativename;
    }

    /**
     * Sets the value of the subjectalternativename property.
     * 
     * @param value
     *            allowed object is {@link SubjectAlternativeNameType }
     * 
     */
    public void setSubjectalternativename(final SubjectAlternativeNameType value) {
        this.subjectalternativename = value;
    }

}
