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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This class contains static methods to throw custom exception of
 * ResponseBuilderException
 * 
 * @author tcsdemi
 *
 */
public class ResponseBuilderExceptionHelper {

    private ResponseBuilderExceptionHelper() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(ResponseBuilderExceptionHelper.class);

    /**
     * This method is used to throw custom exception of ResponseBuilderException<br>
     * eg: catch (IOException ioException) { <br>
     * throw new ResponseBuilderException (UserString.<anyString>, ioException); <br>
     * }
     * 
     * @param errorMessage
     *            This is either a user defined error Message or from thrown
     *            exception i.e <UserDefinedException.getMessage()>
     * @param cause
     *            Throwable object to maintain original stacktrace
     * @throws ResponseBuilderException
     * 
     */
    public static void throwCustomException(final String errorMessage, final Throwable cause) throws ResponseBuilderException {
        LOGGER.error(errorMessage);
        throw new ResponseBuilderException(errorMessage, cause);

    }

    /**
     * This method is used to throw custom exception of ResponseBuilderException<br>
     * eg: catch (IOException ioException) { <br>
     * throw new ResponseBuilderException (ioException); <br>
     * }
     * 
     * @param cause
     *            Throwable object to maintain original stacktrace
     * @throws ResponseBuilderException
     * 
     */
    public static void throwCustomException(final Throwable cause) throws ResponseBuilderException {
        LOGGER.debug("EXCEPTION STACKTRACE: ", cause);
        throw new ResponseBuilderException(cause);

    }

}
