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

import javax.xml.bind.annotation.*;

/**
 * <p>
 * This is the enum of algorithm categories supported.
 * 
 * <p>
 * The following schema fragment specifies the XSD Schema for this class.
 * <p>
 * 
 * <pre>
 * &lt;simpleType name="AlgorithmCategory">
 *   &lt;restriction base="{http://www.w3.org/2001/XMLSchema}string">
 *     &lt;enumeration value="OTHER"/>
 *     &lt;enumeration value="KEY_IDENTIFIER"/>
 *   &lt;/restriction>
 * &lt;/simpleType>
 * </pre>
 * 
 */
@XmlType(name = "AlgorithmCategory")
@XmlEnum
public enum AlgorithmCategory {

    @XmlEnumValue("OTHER")
    OTHER("other", 1), @XmlEnumValue("KEY_IDENTIFIER")
    KEY_IDENTIFIER("key identifier", 2);

    private int id;
    private String category;

    /**
     * Constructs AlgorithmCategory object with id.
     * 
     * @param id
     *            id of the algorithm category to be set.
     */
    private AlgorithmCategory(final String category, final int id) {
        this.category = category;
        this.id = id;
    }

    public String value() {
        return category;
    }

    public static AlgorithmCategory fromValue(final String v) {
        return valueOf(v);
    }

    public int getId() {
        return id;
    }

    /**
     * Get Category of Algorithm Enum from Id.
     * 
     * @param id
     * @return
     */
    public static AlgorithmCategory getCategory(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final AlgorithmCategory algorithmCategory : AlgorithmCategory.values()) {
            if (id.equals(algorithmCategory.getId())) {
                return algorithmCategory;
            }
        }

        throw new IllegalArgumentException("No matching category for id " + id);
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
