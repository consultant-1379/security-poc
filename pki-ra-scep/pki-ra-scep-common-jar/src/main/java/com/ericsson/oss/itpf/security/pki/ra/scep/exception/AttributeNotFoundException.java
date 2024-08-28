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
 * AttributeNotFoundException will be thrown when the mandatory attribute value is not present in the request message from SCEP client.
 *
 * @author xtelsow
 */
public class AttributeNotFoundException extends BadRequestException {

    private static final long serialVersionUID = 1L;

    /**
     * @param msg
     *            is the description of the message.
     */
    public AttributeNotFoundException(final String msg) {
        super(msg);
    }
}
