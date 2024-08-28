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
package com.ericsson.oss.itpf.security.pki.manager.common.exception.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * This is helper class which throws CertificateServiceException
 * 
 * @author tcsdemi
 *
 */
public class CertificateServiceExceptionUtil {

    private static final Logger logger = LoggerFactory.getLogger(CertificateServiceExceptionUtil.class);

    private CertificateServiceExceptionUtil() {

    }

    /**
     * Throws CertificateServiceException
     * 
     * @param cause
     *            exception to be wrapped
     * @throws CertificateServiceException
     */
    public static void throwCertificateServiceException(final Throwable cause) throws CertificateServiceException {
        logger.error("Exception while retrieving certificate {}", cause);
        logger.debug("ExceptionStackTrace: {}", cause);
        throw new CertificateServiceException(cause);

    }

    /**
     * Throws CertificateServiceException
     * 
     * @param cause
     *            exception to be wrapped
     * @param errorMessage
     *            specific error message apart from that present in the exception
     * @throws CertificateServiceException
     */
    public static void throwCertificateServiceException(final Throwable cause, final String errorMessage) throws CertificateServiceException {
        logger.error("Exception occured due to : {}", errorMessage);
        logger.debug("ExceptionStackTrace: {}", cause);
        throw new CertificateServiceException(errorMessage, cause);

    }

}
