/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.credentialsmanagement.xml.model;

import javax.xml.bind.annotation.*;

/**
 * <p>
 * Java class for SubjectType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="SubjectType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="entityname" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="distinguishname" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "SubjectType", propOrder = { "entityName", "distinguishName" })
public class SubjectType {

    @XmlElement(name = "entityname", required = true)
    protected String entityName;
    @XmlElement(name = "distinguishname", required = true)
    protected String distinguishName;

    /**
     * Gets the value of the entityName property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getEntityName() {
        return entityName;
    }

    /**
     * Sets the value of the entityName property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setEntityName(final String value) {
        this.entityName = value;
    }

    /**
     * Gets the value of the distinguishName property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getDistinguishName() {
        return distinguishName;
    }

    /**
     * Sets the value of the distinguishName property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setDistinguishName(final String value) {
        this.distinguishName = value;
    }

}
