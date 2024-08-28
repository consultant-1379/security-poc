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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums;

public enum TDPSEntity {

    CA_ENTITY(1, "CA_ENTITY"), ENTITY(2, "ENTITY"), UNKNOWN(3, "UNKNOWN");

    private int id;
    private String enumString;

    TDPSEntity(final int id, final String enumString) {
        this.id = id;
        this.enumString = enumString;

    }

    /**
     * This method returns the integer value of the ENUM used
     * 
     * @return
     */

    public int getId() {
        return id;
    }

    /**
     * This method returns the string corresponding to the ENUM value.
     * 
     * @return
     */
    public String getValue() {
        return enumString;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
