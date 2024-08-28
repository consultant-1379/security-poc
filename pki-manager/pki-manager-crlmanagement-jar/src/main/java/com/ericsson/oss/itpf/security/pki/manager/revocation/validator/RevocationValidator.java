/*------------------------------------------------------------------------------
 *******************************************************************************
. * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.revocation.validator;

import java.util.Date;
import java.util.EnumSet;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.InvalidInvalidityDateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * This class has the methods that will provide validation for Revocation service. It provides following operations
 * <ul>
 * <li>Validates Issuer certificate status</li>
 * </ul>
 * 
 */

public class RevocationValidator {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Validates each certificate in the list to check for revoked certificates in its chain.
     * 
     * @param certificateDataList
     *            is the CertificateData Class contain the certificate details
     * 
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    public void validateCertificateChain(final List<CertificateData> certificateDataList) throws ExpiredCertificateException, RevocationServiceException, RevokedCertificateException {
        logger.debug("Validate issuer certificate");
        for (CertificateData certificateData : certificateDataList) {
            try {
                certificatePersistenceHelper.validateCertificateChain(certificateData, EnumSet.of(CertificateStatus.REVOKED));
            } catch (final PersistenceException persistenceException) {
                logger.debug("Error occured while validating certificate chain ", persistenceException);
                logger.error("Error occured while validating chain" + persistenceException.getMessage());
                systemRecorder.recordError("PKI_MANAGER_REVOCATION.VALIDATE_CERTIFICATE_CHAIN", ErrorSeverity.ERROR, "Revocation Validator", "Revocation of Certificate",
                        "Error occured while validating certificate chain during revocation for the certificate with serial number" + certificateData.getSerialNumber());
                throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
            }
        }
    }

    /**
     * This method will validate the given invalidityDate for the given CertificateData. The validations is successful when the invalidityDate lies between the dates Certficate validity period.
     * 
     * 
     * @param certificateDataList
     *            List of CertificateData whose invalidityDate need to validate.
     * @param invalidityDate
     *            is the given invalidity date.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     */
    public void validateInvalidityDate(final List<CertificateData> certificateDataList, final Date invalidityDate) throws InvalidInvalidityDateException {
        logger.info("Validating the validity period of the Certificate with the given Date");
        if (invalidityDate != null) {
            for (CertificateData certificateData : certificateDataList) {
                final String certificateDataNotBefore = certificateData.getNotBefore().toString();
                final String certificateDataNotAfter = certificateData.getNotAfter().toString();
                if (invalidityDate.before(certificateData.getNotBefore()) || invalidityDate.after(certificateData.getNotAfter())) {
                    logger.error("{} Given Invalidity date is : {}. It should be with in the certificate validity  {} - {}, with serial number {}", ErrorMessages.INVALID_INVALIDITY_DATE,
                            invalidityDate, certificateDataNotBefore, certificateDataNotAfter, certificateData.getSerialNumber());
                    systemRecorder.recordError("PKI_MANAGER_REVOCATION.INVALID_INVALIDITY_DATE", ErrorSeverity.ERROR, "Revocation Validator", "Revocation of Certificate",
                            ErrorMessages.INVALID_INVALIDITY_DATE + " Given Invalidity date is : " + invalidityDate.toString() + ". It should be with in the certificate validity  "
                                    + certificateData.getNotBefore().toString() + " - " + certificateData.getNotAfter().toString() + ", with serial number " + certificateData.getSerialNumber());
                    throw new InvalidInvalidityDateException(ErrorMessages.INVALID_INVALIDITY_DATE);
                }
            }
        }
    }
}
