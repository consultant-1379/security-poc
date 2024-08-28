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

/**
 * Represents algorithm type.
 * 
 */
public enum AlgorithmType {

    MESSAGE_DIGEST_ALGORITHM("message digest algorithm", 1), SIGNATURE_ALGORITHM("signature algorithm", 2), ASYMMETRIC_KEY_ALGORITHM("asymmetric key algorithm", 3), SYMMETRIC_KEY_ALGORITHM(
            "symmetric key algorithm", 4);

    private int id;
    private String type;

    /**
     * Constructs AlgorithmType object with id.
     * 
     * @param id
     *            id of the algorithm type to be set.
     */
    private AlgorithmType(final String type, final int id) {
        this.type = type;
        this.id = id;
    }

    public String value() {
        return type;
    }

    public static AlgorithmType fromValue(final String v) {
        return valueOf(v);
    }

    public int getId() {
        return id;
    }

    /**
     * Get Type of Algorithm Enum from Id.
     * 
     * @param id
     * @return
     */
    public static AlgorithmType getType(final Integer id) {

        if (id == null) {
            return null;
        }

        for (final AlgorithmType algorithmType : AlgorithmType.values()) {
            if (id.equals(algorithmType.getId())) {
                return algorithmType;
            }
        }

        throw new IllegalArgumentException("No matching type for id " + id);
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
