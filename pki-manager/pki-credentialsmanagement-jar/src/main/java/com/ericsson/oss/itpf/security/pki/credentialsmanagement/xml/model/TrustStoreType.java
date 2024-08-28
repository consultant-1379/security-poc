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
 * Java class for TrustStoreType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="TrustStoreType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *         &lt;choice>
 *           &lt;element name="jkstruststore" type="{}StoreType"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;/choice>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TrustStoreType", propOrder = { "jksTrustStore" })
public class TrustStoreType {

    @XmlElement(name = "jkstruststore", required = true)
    protected StoreType jksTrustStore;

    /**
     * Gets the value of the jksTrustStore property.
     * 
     * @return possible object is {@link StoreType }
     * 
     */
    public StoreType getJksTrustStore() {
        return jksTrustStore;
    }

    /**
     * Sets the value of the jksTrustStore property.
     * 
     * @param value
     *            allowed object is {@link StoreType }
     * 
     */
    public void setJksTrustStore(final StoreType value) {
        this.jksTrustStore = value;
    }
}