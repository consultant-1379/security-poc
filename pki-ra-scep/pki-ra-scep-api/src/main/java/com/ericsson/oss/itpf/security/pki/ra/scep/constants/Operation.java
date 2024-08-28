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
package com.ericsson.oss.itpf.security.pki.ra.scep.constants;

/**
 * This class contains the SCEP protocol related operations which are specified by SCEP Draft. getScepOperation method returns the scepOperation string value to specify the operation type requested by
 * SCEP client.
 *
 * @author xtelsow
 */
public enum Operation {
    PKIOPERATION("PKIOperation"), GETCACAPS("GetCACaps"), GETCACERT("GetCACert"), GETNEXTCACERT("GetNextCACert"), GETCACERTCHAIN("GetCACertChain");

    private String scepOperation;

    Operation(final String value) {
        this.scepOperation = value;
    }

    /**
     * @return the scepOperation
     */
    public String getScepOperation() {
        return scepOperation;
    }

    /**
     * {@inheritDoc}
     *
     * @see java.lang.Enum#toString()
     */
    @Override
    public String toString() {
        return name();
    }
}
