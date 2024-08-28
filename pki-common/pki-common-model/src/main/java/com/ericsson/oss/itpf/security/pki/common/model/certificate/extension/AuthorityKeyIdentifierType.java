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
 * This is the enum of authority key identifier types supported.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="AuthorityKeyIdentifierType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="SUBJECT_KEY_IDENTIFIER"/>
 *     &lt;enumeration value="ISSUER_DN_SERIAL_NUMBER"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "AuthorityKeyIdentifierType")
@XmlEnum
public enum AuthorityKeyIdentifierType {

    @XmlEnumValue("SUBJECT_KEY_IDENTIFIER")
    SUBJECT_KEY_IDENTIFIER(1, "subjectKeyIdentifier"), @XmlEnumValue("ISSUER_DN_SERIAL_NUMBER")
    ISSUER_DN_SERIAL_NUMBER(2, "issuerDNSerialNumber");

    private final int id;
    private final String value;

    AuthorityKeyIdentifierType(final int id, final String v) {
        this.id = id;
        value = v;
    }

    public String getName() {
        return toString();
    }

    /**
     * get String value of AuthorityKeyIdentifierType
     * 
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * get id of a AuthorityKeyIdentifierType
     * 
     * @return id
     */
    public int getId() {
        return id;
    }

    /**
     * Get AuthorityKeyIdentifierType from String value
     * 
     * @param value
     * @return AuthorityKeyIdentifierType Enum
     */
    public static AuthorityKeyIdentifierType fromValue(final String v) {
        for (final AuthorityKeyIdentifierType c : AuthorityKeyIdentifierType.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

    /**
     * Get AuthorityKeyIdentifierType from ID
     * 
     * @param id
     * @return AuthorityKeyIdentifierType Enum
     */
    public static AuthorityKeyIdentifierType fromId(final int id) {
        for (final AuthorityKeyIdentifierType c : AuthorityKeyIdentifierType.values()) {
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
