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
 * NotImplementedOperException will be thrown when Operation requested from node is not yet implemented but supported by SCEP draft.
 *
 * @author xtelsow
 */
public class NotImplementedOperException extends NotImplementedException {

    private static final long serialVersionUID = 1L;

    /**
     * @param msg
     *            is the description of the message.
     */
    public NotImplementedOperException(final String msg) {
        super(msg);
    }

}
