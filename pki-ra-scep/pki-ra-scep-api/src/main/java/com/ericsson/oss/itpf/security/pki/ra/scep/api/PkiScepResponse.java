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
package com.ericsson.oss.itpf.security.pki.ra.scep.api;

import java.io.Serializable;

/**
 * This class is a response holder with message variable which contains response in DER encodable format and content type variable to specify content type of the SCEP response to be sent in response
 * header.
 *
 * @author xtelsow
 */
public class PkiScepResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    private byte[] message = null;

    private String contentType;

    /**
     * @return the message
     */
    public byte[] getMessage() {
        return message;
    }

    /**
     * @param message
     *            the message to set
     */
    public void setMessage(final byte[] message) {
        this.message = message;
    }

    /**
     * @return the contenType
     */
    public String getContentType() {
        return contentType;
    }

    /**
     * @param contenType
     *            the contentType to set
     */
    public void setContentType(final String contenType) {
        this.contentType = contenType;
    }

}
