/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.validator;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * This class is used to validate {@link CertificateStatus} values.
 * 
 * @author xramdag
 * 
 */
public class CertificateStatusValidator {

    @Inject
    Logger logger;

    /**
     * This method is used to check valid certificateStatus values.If any one of the value in certificateStatuses array is "EXPIRED" or "REVOKED" then it will throw ExpiredCertificateException and
     * RevokedCertificateException respectively.
     * 
     * @param certificateStatuses
     *            {@link CertificateStatus} values to be validated
     * 
     * @throws ExpiredCertificateException
     *             thrown when "EXPIRED" certificate status is provided in certificateStatuses array.
     * @throws RevokedCertificateException
     *             thrown when "REVOKED" certificate status is provided in certificateStatuses array.
     */
    public void validate(final CertificateStatus... certificateStatuses) throws ExpiredCertificateException, RevokedCertificateException {
        for (CertificateStatus certStatus : certificateStatuses) {
            logger.debug("CertificateStatus is received as :", certStatus);
            if (certStatus.equals(CertificateStatus.EXPIRED)) {
                logger.error(ErrorMessages.EXPIRED_CERTIFICATE_STATUS);
                throw new ExpiredCertificateException(ErrorMessages.EXPIRED_CERTIFICATE_STATUS);
            } else if (certStatus.equals(CertificateStatus.REVOKED)) {
                logger.error(ErrorMessages.REVOKED_CERTIFICATE_STATUS);
                throw new RevokedCertificateException(ErrorMessages.REVOKED_CERTIFICATE_STATUS);
            }
        }
    }
}
