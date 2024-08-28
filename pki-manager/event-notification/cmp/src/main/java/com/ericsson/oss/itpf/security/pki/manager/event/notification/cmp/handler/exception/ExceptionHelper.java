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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.exception;

/**
 * This class handles all the exceptions occured while building Response.
 * 
 * @author tcsramc
 * 
 */
public class ExceptionHelper {

    private ExceptionHelper() {

    }

    /**
     * This Exception is thrown if any error occur while building response such as CertificateNotFound,EntiotyNotFound,I/O Error... and this method creates an Exception with the errorMessage.
     * 
     * @param errorMessage
     *            Error Message to form exception
     * @param throwable
     *            Exception to be thrown
     * @throws ResponseEventBuilderException
     *             finally forms new exception and throws with the proper errormessage
     */
    public static void throwResponseEventBuilderException(final String errorMessage, final Throwable throwable) throws ResponseEventBuilderException {

        throw new ResponseEventBuilderException(errorMessage, throwable);

    }

}
