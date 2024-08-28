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

import javax.xml.bind.annotation.XmlEnum;
import javax.xml.bind.annotation.XmlType;

/**
 * <p>
 * This enum specifies all the subject alternative fields supported by profile management service.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="SubjectAltNameFieldType">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="RFC822_NAME"/>
 *     &lt;enumeration value="OTHER_NAME"/>
 *     &lt;enumeration value="EDI_PARTY_NAME"/>
 *     &lt;enumeration value="DNS_NAME"/>
 *     &lt;enumeration value="DIRECTORY_NAME"/>
 *     &lt;enumeration value="UNIFORM_RESOURCE_IDENTIFIER"/>
 *     &lt;enumeration value="IP_ADDRESS"/>
 *     &lt;enumeration value="REGESTERED_ID"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "SubjectAltNameFieldType")
@XmlEnum
public enum SubjectAltNameFieldType {

    // Removed X400_ADDRESS from SubjectAltNameFieldType as part of TORF-119907, TORF-117173
    RFC822_NAME(1, SubjectAltNameString.class), OTHER_NAME(2, OtherName.class), EDI_PARTY_NAME(3, EdiPartyName.class), DNS_NAME(4, SubjectAltNameString.class), DIRECTORY_NAME(5,
            SubjectAltNameString.class), UNIFORM_RESOURCE_IDENTIFIER(6, SubjectAltNameString.class), IP_ADDRESS(7, SubjectAltNameString.class), REGESTERED_ID(8, SubjectAltNameString.class);

    private final int id;
    Class<?> classType;

    private SubjectAltNameFieldType(final int id, final Class<?> classType) {
        this.id = id;
        this.classType = classType;

    }

    public String getName() {
        return toString();
    }

    /**
     * get Class Type supported for a SubjectALtName Field.
     * 
     * @return Class
     */
    public Class<?> getClassType() {
        return classType;
    }

    /**
     * get id for a SubjectALtName Field.
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
    public static SubjectAltNameFieldType fromId(final int id) {
        for (final SubjectAltNameFieldType c : SubjectAltNameFieldType.values()) {
            if (c.id == id) {
                return c;
            }
        }
        throw new IllegalArgumentException("Invalid ID : " + id);
    }

    /**
     * Get Enum from name
     * 
     * @param name
     * @return Corresponding Enum
     */
    public static SubjectAltNameFieldType fromName(final String name) {
        for (final SubjectAltNameFieldType c : SubjectAltNameFieldType.values()) {
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
