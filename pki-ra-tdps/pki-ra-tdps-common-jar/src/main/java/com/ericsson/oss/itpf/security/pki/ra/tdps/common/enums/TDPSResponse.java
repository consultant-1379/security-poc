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

/**
 * This enum is used to hold whether any request towards pki-ra-tdps is a success or failure and the same is passed in the Acknowledgment event
 * 
 * @author tcsdemi
 *
 */
public enum TDPSResponse {
    SUCCESS(1, "SUCCESS"), FAILURE(2, "FAILURE"), UNKNOWN_STATUS(3, "UNKNOWN_STATUS");

    private int id;
    private String value;

    TDPSResponse(final int id, final String value) {
        this.id = id;
        this.value = value;

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
        return value;
    }

    @Override
    public String toString() {
        return super.toString();
    }
}
