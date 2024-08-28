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
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;

/**
 * Enum class contains RequestMessage constants
 * 
 * @author tcsramc
 * 
 */
public enum CMPRequestType {
    INITIALIZATION_REQUEST(Constants.TYPE_INIT_REQ, "INITILIZATION REQUEST"), KEY_UPDATE_REQUEST(Constants.TYPE_KEY_UPDATE_REQ, "KEY UPDATE REQUEST"), CERTIFICATE_CONFIRMATION(
            Constants.TYPE_CERT_CONF, "CERTIFICATE CONFIRMATION"), POLL_REQUEST(Constants.TYPE_POLL_REQ, "POLL REQUEST"), INVALID_REQUEST(Constants.INVALID_REQUEST, "INVALID REQUEST");

    private int value;
    private String messageString;

    /**
     * Sets Value and message to ENUM
     * 
     * @param value
     *            value to set
     * @param message
     *            message to set
     */
    private CMPRequestType(final int value, final String message) {
        this.value = value;
        this.messageString = message;

    }

    /**
     * retruns message
     * 
     * @return
     */
    public String toString() {
        return messageString;
    }

    /**
     * retruns value
     * 
     * @return
     */
    public int getValue() {
        return value;
    }

}
