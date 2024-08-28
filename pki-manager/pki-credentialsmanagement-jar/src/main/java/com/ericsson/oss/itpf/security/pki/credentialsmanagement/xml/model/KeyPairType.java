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

import java.math.BigInteger;

import javax.xml.bind.annotation.*;

/**
 * <p>
 * Java class for KeypairType complex type.
 * 
 * <p>
 * The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KeypairType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="keypairsize" type="{http://www.w3.org/2001/XMLSchema}positiveInteger"  minOccurs="1" maxOccurs="unbounded"/>
 *         &lt;element name="keypairalgorithm" type="{http://www.w3.org/2001/XMLSchema}string"  minOccurs="1" maxOccurs="unbounded"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeypairType", propOrder = { "keyPairSize", "keyPairAlgorithm" })
public class KeyPairType {

    @XmlElement(name = "keypairsize", required = true)
    @XmlSchemaType(name = "positiveInteger")
    protected Integer keyPairSize;
    @XmlElement(name = "keypairalgorithm", required = true)
    protected String keyPairAlgorithm;

    /**
     * Gets the value of the keyPairSize property.
     * 
     * @return possible object is {@link BigInteger }
     * 
     */
    public Integer getKeyPairSize() {
        return keyPairSize;
    }

    /**
     * Sets the value of the keyPairSize property.
     * 
     * @param value
     *            allowed object is {@link BigInteger }
     * 
     */
    public void setKeyPairSize(final Integer value) {
        this.keyPairSize = value;
    }

    /**
     * Gets the value of the keyPairAlgorithm property.
     * 
     * @return possible object is {@link String }
     * 
     */
    public String getKeyPairAlgorithm() {
        return keyPairAlgorithm;
    }

    /**
     * Sets the value of the keyPairAlgorithm property.
     * 
     * @param value
     *            allowed object is {@link String }
     * 
     */
    public void setKeyPairAlgorithm(final String value) {
        this.keyPairAlgorithm = value;
    }

}
