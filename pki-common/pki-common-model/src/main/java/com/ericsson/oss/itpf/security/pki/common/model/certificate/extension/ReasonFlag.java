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
 * This enum defines the Reason flags in CRL as per RFC5280.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="ReasonFlag">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *    &lt;enumeration value="UNUSED"/>
 *    &lt;enumeration value="KEY_COMPROMISE" />
 *    &lt;enumeration value="CA_COMPROMISE" />
 *    &lt;enumeration value="AFFILIATION_CHANGED" />
 *    &lt;enumeration value="SUPERSEDED" />
 *    &lt;enumeration value="CESSATION_OF_OPERATION" />
 *    &lt;enumeration value="CERTIFICATE_HOLD" />
 *    &lt;enumeration value="PRIVILEGE_WITHDRAWN" />
 *    &lt;enumeration value="AA_COMPROMISE" />
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "ReasonFlag")
@XmlEnum
public enum ReasonFlag {
    @XmlEnumValue("UNUSED")
    UNUSED(1, "unused"), @XmlEnumValue("KEY_COMPROMISE")
    KEY_COMPROMISE(2, "keyCompromise"), @XmlEnumValue("CA_COMPROMISE")
    CA_COMPROMISE(3, "cACompromise"), @XmlEnumValue("AFFILIATION_CHANGED")
    AFFILIATION_CHANGED(4, "affiliationChanged"), @XmlEnumValue("SUPERSEDED")
    SUPERSEDED(5, "superseded"), @XmlEnumValue("CESSATION_OF_OPERATION")
    CESSATION_OF_OPERATION(6, "cessationOfOperation"), @XmlEnumValue("CERTIFICATE_HOLD")
    CERTIFICATE_HOLD(7, "certificateHold"), @XmlEnumValue("PRIVILEGE_WITHDRAWN")
    PRIVILEGE_WITHDRAWN(8, "privilegeWithdrawn"), @XmlEnumValue("AA_COMPROMISE")
    AA_COMPROMISE(9, "aACompromise");

    private final int id;
    private final String value;

    ReasonFlag(final int id, final String v) {
        this.id = id;
        value = v;

    }

    public String getName() {
        return toString();
    }

    /**
     * get String value of ReasonFlag
     * 
     * @return value
     */
    public String getValue() {
        return value;
    }

    /**
     * get id of a ReasonFlag
     * 
     * @return id
     */
    public int getId() {
        return id;
    }

    /**
     * get ReasonFlag enum from String value.
     * 
     * @param value
     * @return corresponding Enum
     */
    public static ReasonFlag fromValue(final String v) {
        for (final ReasonFlag c : ReasonFlag.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

    /**
     * Get ReasonFlag from ID
     * 
     * @param id
     * @return ReasonFlag Enum
     */
    public static ReasonFlag fromId(final int id) {
        for (final ReasonFlag c : ReasonFlag.values()) {
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
