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
 * This is enum holding various states of an Entity/CAEntity.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema of this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="EntityStatus">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="NEW"/>
 *     &lt;enumeration value="ACTIVE"/>
 *     &lt;enumeration value="INACTIVE"/>
 *     &lt;enumeration value="REISSUE"/>
 *     &lt;enumeration value="DELETED"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "EntityStatus")
@XmlEnum
public enum EntityStatus {
    NEW(1), ACTIVE(2), INACTIVE(3), REISSUE(4), DELETED(5);

    private int id;

    /**
     * 
     */
    private EntityStatus(final int id) {
        this.id = id;
    }

    public int getId() {
        return this.id;
    }

    public String value() {
        return name();
    }

    public static EntityStatus fromValue(final String v) {
        return valueOf(v);
    }

    public static EntityStatus getStatus(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final EntityStatus entityStatus : EntityStatus.values()) {
            if (id.equals(entityStatus.getId())) {
                return entityStatus;
            }
        }

        throw new IllegalArgumentException("No matching status for id " + id);
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
