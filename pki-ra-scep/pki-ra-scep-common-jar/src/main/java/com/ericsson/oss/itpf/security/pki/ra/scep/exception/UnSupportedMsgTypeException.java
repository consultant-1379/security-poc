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
package com.ericsson.oss.itpf.security.pki.ra.scep.exception;

/**
 * UnSupportedMsgTypeException will be thrown when the Message type is not supported.
 *
 * @author xshaeru
 */
public class UnSupportedMsgTypeException extends BadRequestException {
    /**
    *
    */
    private static final long serialVersionUID = 1L;

    /**
     * This exception is thrown if the requested message type is not supported.
     * 
     * @param msg
     *            description of the message.
     */
    public UnSupportedMsgTypeException(final String msg) {
        super(msg);
    }
}
