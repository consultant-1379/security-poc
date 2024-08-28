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
 * This is the enum for Access methods. Currently as per RFC5280 the two access methods supported are: id-ad-caIssuers and id-ad-ocsp
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="AccessMethod">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="CA_ISSUER"/>
 *     &lt;enumeration value="OCSP"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "AccessMethod")
@XmlEnum
public enum AccessMethod {
    @XmlEnumValue("CA_ISSUER")
    CA_ISSUER(1, "1.3.6.1.5.5.7.48.2"), @XmlEnumValue("OCSP")
    OCSP(2, "1.3.6.1.5.5.7.48.1");

    private final int id;
    private final String value;

    AccessMethod(final int id, final String value) {
        this.id = id;
        this.value = value;
    }

    public String getName() {
        return toString();
    }

    /**
     * get String value of AccessMethod
     * 
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * get id of a AccessMethod
     * 
     * @return id
     */
    public int getId() {
        return id;
    }

    /**
     * get Accessmethod enum from String value.
     * 
     * @param value
     * @return corresponding Enum
     */
    public static AccessMethod fromValue(final String v) {
        return valueOf(v);
    }

    /**
     * Get Accessmethod from ID
     * 
     * @param id
     * @return Accessmethod Enum
     */
    public static AccessMethod fromId(final int id) {
        for (final AccessMethod c : AccessMethod.values()) {
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
