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

package com.ericsson.oss.itpf.security.pki.common.model;

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * This is the enum of subject fields supported.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="SubjectFieldType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="COMMON_NAME"/>
 *     &lt;enumeration value="SURNAME"/>
 *     &lt;enumeration value="COUNTRY_NAME"/>
 *     &lt;enumeration value="LOCALITY_NAME"/>
 *     &lt;enumeration value="STATE"/>
 *     &lt;enumeration value="STREET_ADDRESS"/>
 *     &lt;enumeration value="ORGANIZATION"/>
 *     &lt;enumeration value="ORGANIZATION_UNIT"/>
 *     &lt;enumeration value="DN_QUALIFIER"/>
 *     &lt;enumeration value="TITLE"/>
 *     &lt;enumeration value="GIVEN_NAME"/>
 *     &lt;enumeration value="SERIAL_NUMBER"/>
 *     &lt;enumeration value="DC"/>
 *     &lt;enumeration value="INITIALS"/>
 *     &lt;enumeration value="GENERATION"/>
 *     &lt;enumeration value="EMAIL_ADDRESS"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SubjectFieldType")
@XmlEnum
public enum SubjectFieldType {

    COMMON_NAME(1, "CN", "2.5.4.3"), SURNAME(2, "SURNAME", "2.5.4.4"), COUNTRY_NAME(3, "C", "2.5.4.6"), LOCALITY_NAME(4, "L", "2.5.4.7"), STATE(5, "ST", "2.5.4.8"), STREET_ADDRESS(6, "STREET",
            "2.5.4.9"), ORGANIZATION(7, "O", "2.5.4.10"), ORGANIZATION_UNIT(8, "OU", "2.5.4.11"), DN_QUALIFIER(9, "DN", "2.5.4.46"), TITLE(10, "T", "2.5.4.12"), GIVEN_NAME(11, "GIVENNAME", "2.5.4.42"), SERIAL_NUMBER(
            12, "SN", "2.5.4.5"), DC(13, "DC", "0.9.2342.19200300.100.1.25"), INITIALS(14, "INITIALS", "2.5.4.43"), GENERATION(15, "GENERATION", "2.5.4.44"), EMAIL_ADDRESS(16, "E", "1.2.840.113549.1.9.1");

    private final int id;
    private String value;
    private String oid;

    /**
     * 
     */
    private SubjectFieldType(final int id, final String value, final String oid) {
        this.id = id;
        this.value = value;
        this.oid = oid;
    }

    /**
     * Get String Value of Enum
     * 
     * @return String value
     */
    public String getValue() {
        return value;
    }

    public String getName() {
        return toString();
    }

    /**
     * Get OID of Subject Field.
     * 
     * @return OID
     */
    public String getOID() {
        return oid;
    }

    /**
     * get id for a Subject Field.
     * 
     * @return id
     */
    public int getId() {
        return id;
    }

    /**
     * Get Enum from id
     * 
     * @param id
     * @return Corresponding Enum
     */
    public static SubjectFieldType fromId(final int id) {
        for (final SubjectFieldType c : SubjectFieldType.values()) {
            if (c.id == id) {
                return c;
            }
        }
        throw new IllegalArgumentException("Invalid ID : " + id);
    }

    /**
     * Get Subject Type from OID.
     * 
     * @param oid
     * @return Return Subject field Type with given OID
     */
    public static SubjectFieldType fromOID(final String oid) {
        for (final SubjectFieldType subjectFieldType : SubjectFieldType.values()) {
            if (subjectFieldType.oid.equals(oid)) {
                return subjectFieldType;
            }
        }
        throw new IllegalArgumentException("Invalid Subject Type!!");
    }

    /**
     * Get Enum from name
     * 
     * @param name
     * @return Corresponding Enum
     */
    public static SubjectFieldType fromName(final String name) {
        for (final SubjectFieldType c : SubjectFieldType.values()) {
            if (c.name().equals(name)) {
                return c;
            }
        }
        throw new IllegalArgumentException("Invalid name : " + name);
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
