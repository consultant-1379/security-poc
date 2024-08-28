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
 * Java class for KeyStoreType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KeyStoreType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="pkcs12keystore" type="{}StoreType"  minOccurs="1" maxOccurs="unbounded"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyStoreType", propOrder = { "pkcs12KeyStore" })
public class KeyStoreType {

    @XmlElement(name = "pkcs12keystore", required = true)
    protected StoreType pkcs12KeyStore;

    /**
     * Gets the value of the pkcs12KeyStore property.
     * 
     * @return possible object is {@link KStoreType }
     * 
     */
    public StoreType getPkcs12KeyStore() {
        return pkcs12KeyStore;
    }

    /**
     * Sets the value of the pkcs12KeyStore property.
     * 
     * @param value
     *            allowed object is {@link KStoreType }
     * 
     */
    public void setPkcs12Keytore(final StoreType value) {
        this.pkcs12KeyStore = value;
    }

}
