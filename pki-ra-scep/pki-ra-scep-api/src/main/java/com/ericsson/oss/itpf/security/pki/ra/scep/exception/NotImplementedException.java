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
 * NotImplementedException will be thrown when Message Type or operation requested from SCEP client is present in SCEP draft but not implemented .
 *
 * @author xtelsow
 */
public class NotImplementedException extends ProtocolException {

    private static final long serialVersionUID = 1L;

    /**
     * @param msg
     *            is the description of the message.
     */
    public NotImplementedException(final String msg) {
        super(msg);
    }

}
