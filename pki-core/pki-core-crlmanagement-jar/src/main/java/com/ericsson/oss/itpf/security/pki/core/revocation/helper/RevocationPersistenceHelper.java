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
package com.ericsson.oss.itpf.security.pki.core.revocation.helper;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.RevocationRequestData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.util.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;

/**
 * RevocationPersistenceHelper is a helper class for CRUD operations of RevocationData.
 *
 * @author xvambur
 *
 */
public class RevocationPersistenceHelper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method will update the revoked status of certificate
     *
     * @param revocationRequestData
     *            is the RevocationRequestData object for which the certificates need to be updated to revoked status.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    public void updateCertificateStatusForRevocationRequest(final RevocationRequestData revocationRequestData) throws RevocationServiceException {
        logger.debug("Updating certificateStatus for revocation request ");
        try {
            final Set<CertificateData> certData = new HashSet<>();
            for (final CertificateData certificateData : revocationRequestData.getCertificatesToRevoke()) {
                certificateData.setRevokedTime(new Date());
                certificateData.setStatus(CertificateStatus.REVOKED);
                certData.add(certificateData);
            }
            revocationRequestData.setCertificatesToRevoke(certData);
            persistenceManager.updateEntity(revocationRequestData);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while updating certificate status ", persistenceException);
            logger.error("Error occured while updating certificate status {}" , persistenceException.getMessage());
            systemRecorder.recordError("PKI_CORE_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured while updating the certificate status to revoked.");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }
        logger.debug("CertificateStatus for revocation request updated");
    }

    /**
     * This method is used to store the revocation request details
     *
     * @param revocationRequestData
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors in case of Revocation.
     *
     */
    public void storeRevocationRequest(final RevocationRequestData revocationRequestData) throws RevocationServiceException {
        try {
            persistenceManager.createEntity(revocationRequestData);
        } catch (final PersistenceException persistenceException) {
            logger.error("Error occured while persisting RevocationRequestData {}" , persistenceException.getMessage());
            systemRecorder.recordError("PKI_CORE_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured while storing revocation data");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }
    }

    /**
     * This method will update the status of revocationdata as revoked once the whole revocation process is completed.
     *
     * @param revocationRequestData
     * @param status
     *            REVOKED - when the revocation process of the certificate gets completed successfully. FAILED - when the revocation process of the certificate is failed.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors in case of Revocation.
     *
     */
    public void updateRevocationRequestStatus(final RevocationRequestData revocationRequestData, final RevocationRequestStatus status) throws RevocationServiceException {
        try {
            revocationRequestData.setStatus(status);
            persistenceManager.updateEntity(revocationRequestData);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured while updating certificate status ", persistenceException);
            logger.error("Error occured while updating certificate status {} " , persistenceException.getMessage());
            systemRecorder.recordError("PKI_CORE_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationPersistenceHelper", "Revocation of Certificate",
                    "Error occured during updation revocation request status");
            throw new RevocationServiceException(ErrorMessages.INTERNAL_ERROR);
        }

    }

}
