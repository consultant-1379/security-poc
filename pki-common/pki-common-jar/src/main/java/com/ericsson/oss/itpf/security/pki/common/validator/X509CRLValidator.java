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
package com.ericsson.oss.itpf.security.pki.common.validator;

import java.security.cert.X509CRL;
import java.util.Date;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLExpiredException;

/**
 * This class checks the requested X509CRL validity
 * 
 * @author xjagcho
 *
 */
public class X509CRLValidator {
    @Inject
    Logger logger;

    /**
     * This method checks the CRL validity of the requested X509CRL
     * 
     * @param crlToVerify
     *            it contains X509 CRL
     * @throws CRLExpiredException
     *             when exception throws if requested CRL is expired or not
     */
    public void checkCRLvalidity(final X509CRL crlToVerify) throws CRLExpiredException {
        Date nextUpdate = null;
        nextUpdate = crlToVerify.getNextUpdate();
        final Date currentDate = new Date();
        if (nextUpdate != null) {
            if (!nextUpdate.after(currentDate)) {
                logger.error(ErrorMessages.CRL_EXPRIED);
                throw new CRLExpiredException(ErrorMessages.CRL_EXPRIED);
            }
        }
    }
}
