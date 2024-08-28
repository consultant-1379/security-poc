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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.validator;

import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.RevocationRequestData;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.util.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

/**
 * This class is used to perform few validations before processing the revocation request.
 * 
 * @author xvenkat
 * 
 */
public class RevocationRequestValidator {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to validate entity and certificate for which the revocation request is raised.
     * 
     * @param revocationRequestData
     *            RevocationRequestData object which contains the details regarding the revocation request like CAEntity,Entity, RevocationReason etc
     * @throws CertificateExpiredException
     *             Thrown when revocation/crl operations are requested for a expired certificate.
     * @throws CertificateNotFoundException
     *             thrown to indicate Certificate does not exist in PKI-Core.
     * @throws CertificatePathValidationException
     *             thrown to indicate Issuer of the given Entity Certificate is already revoked.
     * @throws CertificateRevokedException
     *             Thrown when revocation/crl operations are requested for a revoked certificate.
     * @throws CoreEntityNotFoundException
     *             thrown when the certificates for which the revocation request is raised is not found.
     * @throws RootCARevocationException
     *             Thrown to indicate Root CA cannot be revoked.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors or any unconditional exceptions.
     */
    public void validate(final RevocationRequestData revocationRequestData) throws CertificateExpiredException, CertificateNotFoundException, CertificatePathValidationException,
            CertificateRevokedException, CoreEntityNotFoundException, RootCARevocationException, RevocationServiceException {
        if (revocationRequestData.getCaEntity() == null && revocationRequestData.getEntity() == null) {
            logger.error("Entity/CAEntity being revoked is not found");
            systemRecorder.recordError("PKI_CORE_REVOCATION.INTERNAL_ERROR", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation of Certificate",
                    "Entity/CAEntity being revoked is not set to Revocation Request.");
            throw new CoreEntityNotFoundException(ErrorMessages.ENTITY_NOT_FOUND);
        }
        if (revocationRequestData.getCertificatesToRevoke() == null) {
            logger.error("Certificates to be revoked not found");
            systemRecorder.recordError("PKI_CORE_REVOCATION.INTRNAL_ERROR", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation of Certificate",
                    "Certificates to be revoked not found in the Revocation Request");
            throw new CertificateNotFoundException(ErrorMessages.CERTIFICATE_NOT_FOUND);
        }
        if (revocationRequestData.getCaEntity() != null) {
            if (revocationRequestData.getCaEntity().isRootCA()) {
                if (revocationRequestData.getCaEntity().isIssuerExternalCA()) {
                    logger.error("Root CA{}", revocationRequestData.getCaEntity().getName(), "cannot be revoked. Root CA is sub CA of External CA");
                    systemRecorder.recordSecurityEvent("PKI_CORE_REVOCATION.ROOT_CA_REVOCATION", "Revocation of Certificate", "Root CA " + revocationRequestData.getCaEntity().getName()
                            + " can not be revoked and is the SubCA of External CA.", "ROOT CA REVOCATION", ErrorSeverity.ERROR, "FAILURE");
                    throw new RootCARevocationException(ErrorMessages.ROOT_CA_SIGNED_WITH_EXTERNAL_CA_CANNOT_BE_REVOKED);

                }
                systemRecorder.recordSecurityEvent("PKI_CORE_REVOCATION.ROOT_CA_REVOCATION", "Revocation of Certificate", "Root CA " + revocationRequestData.getCaEntity().getName()
                        + " can not be revoked.", "ROOT CA REVOCATION", ErrorSeverity.ERROR, "FAILURE");
                throw new RootCARevocationException(ErrorMessages.ROOT_CA_CANNOT_BE_REVOKED);
            }
        }
        validateCertificateAndIssuerCertificateStatus(revocationRequestData.getCertificatesToRevoke());
        checkRevocationEntityToCertificateMapping(revocationRequestData);
    }

    /**
     * This method checks if the certificatesToRevoke are actually mapped to the entity/caEntity that has to be revoked
     * 
     * @param revocationRequestData
     *            RevocationRequestData object which contains the details regarding the revocation request like CAEntity,Entity, RevocationReason etc
     * @throws CertificateNotFoundException
     *             thrown to report that the Data in PKI Core is out of Sync from PKI Manager.
     */

    private void checkRevocationEntityToCertificateMapping(final RevocationRequestData revocationRequestData) throws CertificateNotFoundException {
        for (CertificateData certificateToBeRevoked : revocationRequestData.getCertificatesToRevoke()) {
            if (revocationRequestData.getCaEntity() != null) {
                if (!revocationRequestData.getCaEntity().getCertificateDatas().contains(certificateToBeRevoked)) {
                    logger.error("Mismatch in RevocationRequest, certificatesToRevoke does match to certificates of caEntity to be revoked");
                    systemRecorder.recordError("PKI_CORE_REVOCATION.NO_CERTIFICATE_FOUND", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation Manager",
                            "Certificates to revoke does match to certificates of Entity " + revocationRequestData.getCaEntity().getName() + " to be revoked.");
                    throw new CertificateNotFoundException(com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages.DATA_OUT_OF_SYNC);
                }
            }
            if (revocationRequestData.getEntity() != null) {
                if (!revocationRequestData.getEntity().getCertificateDatas().contains(certificateToBeRevoked)) {
                    logger.error("Mismatch in RevocationRequest, certificatesToRevoke does match to certificates of entity to be revoked");
                    systemRecorder.recordError("PKI_CORE_REVOCATION.NO_CERTIFICATE_FOUND", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation Manager",
                            "Certificates to revoke does match to certificates of Entity " + revocationRequestData.getEntity() + " to be revoked.");
                    throw new CertificateNotFoundException(com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages.DATA_OUT_OF_SYNC);
                }
            }
        }
    }

    /**
     * This method is used to validate the certificate for which the revocation request is raised. It checks if the certificate is already revoked or expired. It also makes sure that the issuer
     * certificate is not revoked.
     * 
     * @param certificateDataList
     *            List of certificateData
     * @throws CertificateExpiredException
     *             thrown when revocation operation is requested for a expired certificate.
     * @throws CertificatePathValidationException
     *             thrown to indicate Issuer of the given Entity Certificate is already revoked.
     * @throws CertificateRevokedException
     *             thrown when revocation operation is requested for a revoked certificate.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws RootCARevocationException
     *             thrown when the revocation operation is requested for a self signed certificate.
     */
    private void validateCertificateAndIssuerCertificateStatus(final Set<CertificateData> certificateDataList) throws CertificateExpiredException, CertificatePathValidationException,
            CertificateRevokedException, RootCARevocationException {
        logger.debug("Validate issuer certificate");
        for (CertificateData certificateData : certificateDataList) {

            if (certificateData.getStatus().equals(CertificateStatus.EXPIRED)) {
                logger.error("Entity certificate is invalid for revocation");
                systemRecorder.recordError("PKI_CORE_REVOCATION.CERTIFICATE_EXPIRED", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation of Certificate",
                        "Entity certificate with serial number " + certificateData.getSerialNumber() + " is expired for revocation");
                throw new CertificateExpiredException(ErrorMessages.INVALID_CERTIFICATE);
            } else if (certificateData.getStatus().equals(CertificateStatus.REVOKED)) {
                logger.error("Entity certificate is invalid for revocation");
                systemRecorder.recordError("PKI_CORE_REVOCATION.CERTIFICATE_REVOkED", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation of Certificate",
                        "Entity certificate with serial number " + certificateData.getSerialNumber() + " is already revoked");
                throw new CertificateRevokedException(ErrorMessages.INVALID_CERTIFICATE);
            }
            if (certificateData.getIssuerCertificate() != null) {
                validateCertificateChain(certificateData.getIssuerCertificate());
            } else {
                throw new RootCARevocationException(" Self Signed Certificate with serial number " + certificateData.getSerialNumber() + " can not be revoked.");
            }
        }
    }

    // This as to be made reusable where ever it is useful To do TORF-82625
    private void validateCertificateChain(final CertificateData certificateData) throws CertificatePathValidationException {

        if (certificateData.getStatus().equals(CertificateStatus.REVOKED)) {
            systemRecorder.recordError("PKI_CORE_REVOCATION.CERTIFICATE_REVOKED", ErrorSeverity.ERROR, "RevocationRequestValidator", "Revocation of Certifiate",
                    "Issuer certificate with serial number " + certificateData.getSerialNumber() + " is already revoked.");
            throw new CertificatePathValidationException(ErrorMessages.ISSUER_CERTIFICATE_ALREADY_REVOKED);
        }

        if (certificateData.getIssuerCertificate() != null) {
            validateCertificateChain(certificateData.getIssuerCertificate());
        }
    }
}
