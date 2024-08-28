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
 * Java class for TStoreType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="StoreType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="storealias" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *           &lt;element name="storelocation" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="storepassword" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "StoreType", propOrder = { "storeAlias", "storeLocation", "storePassword" })
public class StoreType {

    @XmlElement(name = "storealias", required = true)
    protected String storeAlias;
    @XmlElement(name = "storelocation", required = true)
    protected String storeLocation;
    @XmlElement(name = "storepassword", required = true)
    protected String storePassword;

    /**
     * Gets the value of the storeAlias property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getStoreAlias() {
        return storeAlias;
    }

    /**
     * Sets the value of the storeAlias property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setStoreAlias(final String value) {
        this.storeAlias = value;
    }

    /**
     * Gets the value of the storeLocation property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getStoreLocation() {
        return storeLocation;
    }

    /**
     * Sets the value of the storstoreLocationelocation property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setStoreLocation(final String value) {
        this.storeLocation = value;
    }

    /**
     * Gets the value of the storePassword property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getStorePassword() {
        return storePassword;
    }

    /**
     * Sets the value of the storePassword property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setStorePassword(final String value) {
        this.storePassword = value;
    }

}
