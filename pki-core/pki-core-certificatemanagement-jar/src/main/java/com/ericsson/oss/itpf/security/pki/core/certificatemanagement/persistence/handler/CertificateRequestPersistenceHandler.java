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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler;

import javax.inject.Inject;
import javax.persistence.EntityExistsException;
import javax.persistence.TransactionRequiredException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;

public class CertificateRequestPersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateModelMapper modelMapper;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Stores {@link CertificateGenerationInfoData}, {@link CertificateAuthorityData} and {@link CertificateRequestData} in the database.
     *
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} to be persisted in the database.
     * @param certificateRequest
     *            {@link CertificateRequestData} to be saved in the database.
     * @param entityData
     *            {@link EntityInfoData} to be saved in the database.
     * @return {@link CertificateGenerationInfoData} persisted in the database.
     * @throws CertificateGenerationException
     *             thrown when Certificate generation info is already present in the db.
     * @throws CertificateServiceException
     *             thrown when CertificateRequest save failed.
     * @throws CoreEntityNotFoundException
     *             thrown when entity is not found in the system.
     * @throws CoreEntityServiceException
     *             thrown when db error occurred for entity operations.
     */
    public CertificateGenerationInfoData storeCertificateGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo, final byte[] certificateRequest, final EntityInfoData entityData,
            final CertificateData certificateData) throws CertificateGenerationException, CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException {

        return storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequest, null, entityData, certificateData);
    }

    /**
     * Stores {@link CertificateGenerationInfoData}, {@link CertificateAuthorityData} and {@link CertificateRequestData} in the database.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} to be persisted in the database.
     * @param certificateRequest
     * @param certificateAuthorityData
     *            {@link CertificateAuthorityData} to be saved in the database.
     * @param entityData
     *            {@link EntityInfoData} to be saved in the database.
     * @return {@link CertificateGenerationInfoData} persisted in the database.
     * @throws CertificateGenerationException
     *             thrown when CertificateRequest generation is failed.
     * @throws CertificateServiceException
     *             thrown when CertificateRequest save failed.
     * @throws CoreEntityNotFoundException
     *             Thrown for any entity not found in PKI Core.
     * @throws CoreEntityServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * 
     * 
     */
    public CertificateGenerationInfoData storeCertificateGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo, final byte[] certificateRequest,
            final CertificateAuthorityData certificateAuthorityData, final EntityInfoData entityData) throws CertificateGenerationException, CertificateServiceException, CoreEntityNotFoundException,
            CoreEntityServiceException {

        final CertificateGenerationInfoData certificateGenerationInfoData = modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificateRequest, certificateAuthorityData,
                entityData);

        try {
            persistenceManager.createEntity(certificateGenerationInfoData);
        } catch (EntityExistsException exception) {
            logger.error("{} for entity {}", ErrorMessages.CERTIFICATE_GENERATION_INFO_ALREADY_EXISTS, certificateGenerationInfo.getCAEntityInfo().getName());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CSRManager", "CertificateRequestPersistenceHandler",
                    "Certificate generation info already exists in the system for entity " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_INFO_ALREADY_EXISTS, exception);
        } catch (TransactionRequiredException exception) {
            logger.error("{} for entity {}", ErrorMessages.INTERNAL_ERROR, certificateGenerationInfo.getCAEntityInfo().getName());
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CSRManager", "CertificateRequestPersistenceHandler",
                    "An error occured while processing the request for entity "
                            + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }

        return certificateGenerationInfoData;
    }

    /**
     * Stores {@link CertificateGenerationInfoData}, {@link CertificateAuthorityData} and {@link CertificateRequestData} in the database.
     *
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo} to be persisted in the database.
     * @param certificateRequest
     * @param certificateAuthorityData
     *            {@link CertificateAuthorityData} to be saved in the database.
     * @param entityData
     *            {@link EntityInfoData} to be saved in the database.
     * @param certificateData
     *            {@link CertificateData} to be saved in the database.
     * @return {@link CertificateGenerationInfoData} persisted in the database.
     * @throws CertificateGenerationException
     *             thrown when CertificateRequest generation is failed.
     * @throws CertificateServiceException
     *             thrown when CertificateRequest save failed.
     * @throws CoreEntityNotFoundException
     *             Thrown for any entity not found in PKI Core.
     * @throws CoreEntityServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * 
     * 
     */
    public CertificateGenerationInfoData storeCertificateGenerationInfo(final CertificateGenerationInfo certificateGenerationInfo, final byte[] certificateRequest,
            final CertificateAuthorityData certificateAuthorityData, final EntityInfoData entityData, final CertificateData certificateData) throws CertificateGenerationException,
            CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException {

        final CertificateGenerationInfoData certificateGenerationInfoData = modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, certificateRequest, certificateAuthorityData,
                entityData);
        certificateGenerationInfoData.setCertificateData(certificateData);
        try {
            persistenceManager.createEntity(certificateGenerationInfoData);
        } catch (EntityExistsException exception) {
            logger.error(ErrorMessages.CERTIFICATE_GENERATION_INFO_ALREADY_EXISTS);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificateRequestPersistenceHandler",
                    "CertificateGenerationInfo", "Certificate generation info already exists in the system");
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_GENERATION_INFO_ALREADY_EXISTS, exception);
        } catch (TransactionRequiredException exception) {
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "CertificateRequestPersistenceHandler",
                    "CertificateGenerationInfo", "An error occured while storing certificate generation info");
            logger.error(ErrorMessages.INTERNAL_ERROR);
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, exception);
        }

        return certificateGenerationInfoData;
    }

    /**
     * Updates {@link CSR} to failed state in the database.
     *
     * @param certificateRequestData
     *            {@link CertificateRequestData} to be updated in the database.
     * @throws CertificateServiceException
     *             thrown when CertificateRequest status update failed.
     * 
     */
    public void updateCertificateRequestStatus(final CertificateRequestData certificateRequestData) throws CertificateServiceException {

        certificateRequestData.setStatus(CertificateRequestStatus.FAILED.getId());
        try {
            persistenceManager.updateEntity(certificateRequestData);
        } catch (TransactionRequiredException exception) {
            logger.error(ErrorMessages.CSR_STATUS_UPDATION_FAILED);
            throw new CertificateServiceException(ErrorMessages.CSR_STATUS_UPDATION_FAILED, exception);
        }
    }
}
