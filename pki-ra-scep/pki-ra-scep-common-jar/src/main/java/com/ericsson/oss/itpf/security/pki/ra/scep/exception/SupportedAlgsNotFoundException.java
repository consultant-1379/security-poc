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
 * SupportedAlgsNotFoundException will be thrown when the supported algorithms are not found in cache.
 *
 * @author xshaeru
 */
public class SupportedAlgsNotFoundException extends PkiScepServiceException {
    /**
    *
    */
    private static final long serialVersionUID = 1L;

    /**
     * This exception is thrown if the requested algorithm is not supported
     * 
     * @param msg
     *            description of the message.
     */
    public SupportedAlgsNotFoundException(final String msg) {
        super(msg);
    }
}
