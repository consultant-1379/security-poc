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
 * BadMessageCheckException will be thrown if the Signature on the PKCS7 SCEP Request message is invalid.
 *
 * @author xshaeru
 */
public class BadMessageCheckException extends BadRequestException {

    private static final long serialVersionUID = 1L;

    /**
     * @param msg
     *            is the description of the message.
     */
    public BadMessageCheckException(final String msg) {
        super(msg);
    }
}
