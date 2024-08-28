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

import javax.xml.bind.annotation.*;

/**
 * <p>
 * This enum contains all the supported key usage types as per RFC5280.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="KeyUsageType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="DIGITAL_SIGNATURE"/>
 *     &lt;enumeration value="NON_REPUDIATION"/>
 *     &lt;enumeration value="KEY_ENCIPHERMENT"/>
 *     &lt;enumeration value="DATA_ENCIPHERMENT"/>
 *     &lt;enumeration value="KEY_AGREEMENT"/>
 *     &lt;enumeration value="KEY_CERT_SIGN"/>
 *     &lt;enumeration value="CRL_SIGN"/>
 *     &lt;enumeration value="ENCIPHER_ONLY"/>
 *     &lt;enumeration value="DECIPHER_ONLY"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "KeyUsageType")
@XmlEnum
public enum KeyUsageType {

    @XmlEnumValue("DIGITAL_SIGNATURE")
    DIGITAL_SIGNATURE(0, "digitalSignature"), @XmlEnumValue("NON_REPUDIATION")
    NON_REPUDIATION(1, "nonRepudiation"), @XmlEnumValue("KEY_ENCIPHERMENT")
    KEY_ENCIPHERMENT(2, "keyEncipherment"), @XmlEnumValue("DATA_ENCIPHERMENT")
    DATA_ENCIPHERMENT(3, "dataEncipherment"), @XmlEnumValue("KEY_AGREEMENT")
    KEY_AGREEMENT(4, "keyAgreement"), @XmlEnumValue("KEY_CERT_SIGN")
    KEY_CERT_SIGN(5, "keyCertSign"), @XmlEnumValue("CRL_SIGN")
    CRL_SIGN(6, "cRLSign"), @XmlEnumValue("ENCIPHER_ONLY")
    ENCIPHER_ONLY(7, "encipherOnly"), @XmlEnumValue("DECIPHER_ONLY")
    DECIPHER_ONLY(8, "decipherOnly");

    private final int id;
    private final String value;

    KeyUsageType(final int id, final String v) {
        this.id = id;
        value = v;
    }

    public String getName() {
        return toString();
    }

    /**
     * get String value of KeyUsageType
     * 
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * get id of a KeyUsageType
     * 
     * @return id
     */
    public int getId() {
        return id;
    }

    /**
     * Get KeyUsageType from String value
     * 
     * @param value
     * @return KeyUsageType Enum
     */
    public static KeyUsageType fromValue(final String v) {
        for (final KeyUsageType c : KeyUsageType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

    /**
     * Get KeyUsageType from ID
     * 
     * @param id
     * @return KeyUsageType Enum
     */
    public static KeyUsageType fromId(final int id) {
        for (final KeyUsageType c : KeyUsageType.values()) {
            if (c.id == id) {
                return c;
            }
        }
        throw new IllegalArgumentException("Invalid ID : " + id);
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return super.toString();
    }

}
