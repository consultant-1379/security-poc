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
package com.ericsson.oss.itpf.security.credmservice.api.model;

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
public enum CredentialManagerReasonFlag {
    @XmlEnumValue("UNUSED")
    UNUSED("unused"), @XmlEnumValue("KEY_COMPROMISE")
    KEY_COMPROMISE("keyCompromise"), @XmlEnumValue("CA_COMPROMISE")
    CA_COMPROMISE("cACompromise"), @XmlEnumValue("AFFILIATION_CHANGED")
    AFFILIATION_CHANGED("affiliationChanged"), @XmlEnumValue("SUPERSEDED")
    SUPERSEDED("superseded"), @XmlEnumValue("CESSATION_OF_OPERATION")
    CESSATION_OF_OPERATION("cessationOfOperation"), @XmlEnumValue("CERTIFICATE_HOLD")
    CERTIFICATE_HOLD("certificateHold"), @XmlEnumValue("PRIVILEGE_WITHDRAWN")
    PRIVILEGE_WITHDRAWN("privilegeWithdrawn"), @XmlEnumValue("AA_COMPROMISE")
    AA_COMPROMISE("aACompromise");

    private final String value;

    CredentialManagerReasonFlag(final String v) {
        value = v;
    }

    public String value() {
        return value;
    }

    public static CredentialManagerReasonFlag fromValue(final String v) {
        for (final CredentialManagerReasonFlag c : CredentialManagerReasonFlag.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
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
