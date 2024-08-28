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
package com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception;

import javax.ejb.ApplicationException;

/**
 * This exception is thrown in case of any exceptions while building Responses.
 * 
 * @author tcsdemi
 *
 */
@ApplicationException(rollback = true)
public class ResponseBuilderException extends RuntimeException {

    private static final long serialVersionUID = -145124141534700612L;

    public ResponseBuilderException() {
        super();
    }

    public ResponseBuilderException(final String errorMessage) {
        super(errorMessage);
    }

    /**
     * This exception is thrown in case exceptions need to be wrapped as customException while building Responses.
     * 
     * @param cause
     *            This is a throwable object to maintain original stacktrace of the exception. <br>
     *            eg: catch (IOException ioException) { <br>
     *            throw new ResponseBuilderException (ioException); <br>
     *            }
     */
    public ResponseBuilderException(final Throwable cause) {
        super(cause);
    }

    public ResponseBuilderException(final String errorMessage, final Throwable cause) {
        super(errorMessage, cause);
    }

}
