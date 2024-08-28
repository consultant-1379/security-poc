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
package com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception;

import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;

/**
 * This exception is thrown when Body of the RequestMessage contains message
 * content other than<br>
 * 1. Initialization Request<br>
 * 2. Key Update Request<br>
 * 3. Poll Request<br>
 * 4. Certificate Confirmation Request <br>
 */

public class BodyValidationException extends ValidationException {

    private static final long serialVersionUID = 5912936601783305843L;

    /**
     * This exception is thrown when Body of the RequestMessage contains message
     * content other than<br>
     * 1. Initialization Request<br>
     * 2. Key Update Request<br>
     * 3. Poll Request<br>
     * 4. Certificate Confirmation Request <br>
     * 
     * @param errorMessage
     *            It is the user defined error message
     */
    public BodyValidationException(final String errorMessage) {
        super(errorMessage);
    }

}
