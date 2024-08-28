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
 * This enum contains all the key purpose ids supported as per RFC5280.
 * 
 * <p>
 * 
 * The following schema fragment specifies the XSD Schema of this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="KeyPurposeId">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="ANY_EXTENDED_KEY_USAGE"/>
 *     &lt;enumeration value="ID_KP_CLIENT_AUTH"/>
 *     &lt;enumeration value="ID_KP_CODE_SIGNING"/>
 *     &lt;enumeration value="ID_KP_EMAIL_PROTECTION"/>
 *     &lt;enumeration value="ID_KP_TIMESTAMPING"/>
 *     &lt;enumeration value="ID_KP_OCSP_SIGNING"/>
 *     &lt;enumeration value="ID_KP_SERVER_AUTH"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "KeyPurposeId")
@XmlEnum
public enum KeyPurposeId {
    @XmlEnumValue("ID_KP_SERVER_AUTH")
    ID_KP_SERVER_AUTH(1, "id_kp_serverAuth", "1.3.6.1.5.5.7.3.1"), @XmlEnumValue("ID_KP_CLIENT_AUTH")
    ID_KP_CLIENT_AUTH(2, "id_kp_clientAuth", "1.3.6.1.5.5.7.3.2"), @XmlEnumValue("ID_KP_CODE_SIGNING")
    ID_KP_CODE_SIGNING(3, "id_kp_codeSigning", "1.3.6.1.5.5.7.3.3"), @XmlEnumValue("ID_KP_EMAIL_PROTECTION")
    ID_KP_EMAIL_PROTECTION(4, "id_kp_emailProtection", "1.3.6.1.5.5.7.3.4"), @XmlEnumValue("ID_KP_TIME_STAMPING")
    ID_KP_TIME_STAMPING(5, "id_kp_timeStamping", "1.3.6.1.5.5.7.3.8"), @XmlEnumValue("ID_KP_OCSP_SIGNING")
    ID_KP_OCSP_SIGNING(6, "id_kp_OCSPSigning", "1.3.6.1.5.5.7.3.9"), @XmlEnumValue("ANY_EXTENDED_KEY_USAGE")
    ANY_EXTENDED_KEY_USAGE(7, "anyExtendedKeyUsage", "2.5.29.37.0");

    private final int id;
    private final String value;
    private final String oid;

    KeyPurposeId(final int id, final String v, final String oid) {
        this.id = id;
        value = v;
        this.oid = oid;
    }

    public String getName() {
        return toString();
    }

    /**
     * get String value of a KeyPurposeId
     * 
     * @return String value
     */
    public String getValue() {
        return value;
    }

    /**
     * get OID of a KeyPurposeID
     * 
     * @return OID
     */
    public String getOID() {
        return oid;
    }

    /**
     * get ID of a KeyPurposeID
     * 
     * @return ID
     */
    public int getId() {
        return id;
    }

    /**
     * Get Enum from String value
     * 
     * @param value
     * @return Corresponding Enum
     */
    public static KeyPurposeId fromValue(final String v) {
        for (final KeyPurposeId c : KeyPurposeId.values()) {
            if (c.value.equals(v)) {
                return c;
            }
        }
        throw new IllegalArgumentException(v);
    }

    /**
     * Get Enum from id
     * 
     * @param id
     * @return Corresponding Enum
     */
    public static KeyPurposeId fromId(final int id) {
        for (final KeyPurposeId c : KeyPurposeId.values()) {
            if (c.id == id) {
                return c;
            }
        }
        throw new IllegalArgumentException("Invalid ID : " + id);
    }

    /**
     * Get Enum from oid
     * 
     * @param oid
     * @return Corresponding Enum
     */
    public static KeyPurposeId fromOid(final String oid) {
        for (final KeyPurposeId c : KeyPurposeId.values()) {
            if (c.oid.equals(oid)) {
                return c;
            }
        }
        throw new IllegalArgumentException("Invalid OID : " + oid);
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
