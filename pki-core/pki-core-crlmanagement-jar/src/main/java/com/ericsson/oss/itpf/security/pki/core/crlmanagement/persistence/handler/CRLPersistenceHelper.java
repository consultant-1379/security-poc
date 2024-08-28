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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.persistence.handler;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CRLInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

/**
 * This Helper class provides methods that help in retrieving various CRL related data.
 *
 */
public class CRLPersistenceHelper {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CRLInfoMapper cRLInfoMapper;

    @Inject
    CertificateAuthorityModelMapper modelMapper;

    @Inject
    CRLGenerationInfoMapper crlGenerationInfoMapper;

    @Inject
    private SystemRecorder systemRecorder;

    private final static String NAME_PATH = "name";
    private final static String CRL_STATUS = "status";

    // TODO: Configuration of DB queries will be analyzed as part of the spike TORF-83179
    private final static String getCRLWithMaxNumberQuery = "SELECT c FROM CRLInfoData c WHERE c.certificateData.id =(:certificateId) AND c.crlNumber  = ( SELECT MAX(c.crlNumber) FROM c WHERE  c.certificateData.id =(:certificateId))";
    private static final String getOverlapPeriodForCRLNativeQuery = "SELECT overlap_period FROM crl_generation_info WHERE id =( SELECT crl_generation_info_id FROM crl_generation_info_ca_certificate WHERE certificate_id= :certId)";

    /**
     * Retrieves the {@link CertificateAuthorityData} by building a criteria query from CA name
     *
     * @param cAName
     *            name of CA
     * @return CertificateAuthorityData retrieved from database
     * @throws CoreEntityNotFoundException
     *             Thrown in case given CA not found in the database.
     * @throws CRLServiceException
     *             Thrown in case PersistenceException occurred while fetching CertificateAuthorityData information from DB.
     * @throws CRLGenerationException
     *             Thrown when any exception occurred during CRLGeneration.
     * @throws InvalidCertificateException
     *             thrown when Invalid certificate is found for entity.
     * @throws InvalidCRLGenerationInfoException
     *             thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public CertificateAuthority getCertificateAuthority(final String cAName) throws CoreEntityNotFoundException, CRLServiceException, InvalidCertificateException, InvalidCRLGenerationInfoException {
        logger.debug("Retrieving certificate authority data for CA : {}", cAName);
        try {
            final CertificateAuthorityData certificateAuthorityData = persistenceManager.findEntityByName(CertificateAuthorityData.class, cAName, NAME_PATH);
            if (certificateAuthorityData == null) {
                logger.error(ErrorMessages.CERTIFICATE_AUTHORITY_NOT_FOUND + " for {}" , cAName);
                systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.CERTIFICATE_AUTHORITY_NOT_FOUND", ErrorSeverity.ERROR, "CRLPersistenceHelper", "Get/Generate CRL",
                        "Certificate authority With Name : " + cAName + " does not exist.");
                throw new CoreEntityNotFoundException(ErrorMessages.CERTIFICATE_AUTHORITY_NOT_FOUND);
            }
            return modelMapper.toAPIModel(certificateAuthorityData);
        } catch (final PersistenceException e) {
            logger.debug(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, e);
            logger.error(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE);
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLPersistenceHelper", "Get/Generate CRL",
                    "Error occured while fetching Certificate authority with name : " + cAName + ".");
            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE);
        }
    }

    /**
     * This method will update CRL status to EXPIRED for all crls whose validity has expired.
     *
     * @throws CRLServiceException
     *             Thrown when update entity failed.
     */
    public void updateCRLStatusToExpired() throws CRLServiceException {
        logger.info("Updating the CRL status to expired in pki-core");
        int updatedEntityCount = 0;
        final List<CRLInfoData> cRLDataList = getCRLDataByStatus(CRLStatus.INVALID, CRLStatus.LATEST, CRLStatus.OLD);
        if (cRLDataList != null) {
            for (final CRLInfoData cRLInfoData : cRLDataList) {
                if (cRLInfoData.getNextUpdate().compareTo(new Date()) <= 0) {
                    cRLInfoData.setStatus(CRLStatus.EXPIRED);
                    try {
                        persistenceManager.updateEntity(cRLInfoData);
                    } catch (final PersistenceException e) {
                        logger.error("Unexpected Error while Updating the entity {}. {}", cRLInfoData.getClass(), e.getMessage());
                        systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.UPDATE_CRLSTATUS_FAILURE", ErrorSeverity.ERROR, "CRLPersistenceHelper", "Updation of CRL status to expired",
                                "Error occured while updating the status to EXPIRED for CRLInfo of the CA certificate with serial number : " + cRLInfoData.getCertificateData().getSerialNumber());
                        throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", e);
                    }
                    updatedEntityCount++;
                }
            }
        }
        logger.debug("Updated CRL status to expired for {} entities", updatedEntityCount);
    }

    /**
     * This method will update CRL status to INVALID whose issuer certificate has revoked.
     *
     * @throws CRLServiceException
     *             Thrown when update entity failed.
     */
    public void updateCRLStatusToInvalid() throws CRLServiceException {
        logger.debug("Updating the crl status to invalid in pki-core");
        int updatedEntityCount = 0;
        final List<CRLInfoData> cRLDataList = getCRLDataByStatus(CRLStatus.LATEST, CRLStatus.OLD);
        if (cRLDataList != null) {
            for (final CRLInfoData cRLInfoData : cRLDataList) {
                final CertificateStatus crlIssuerCertStatus = cRLInfoData.getCertificateData().getStatus();
                if (crlIssuerCertStatus == CertificateStatus.REVOKED || crlIssuerCertStatus == CertificateStatus.EXPIRED) {
                    cRLInfoData.setStatus(CRLStatus.INVALID);
                    try {
                        persistenceManager.updateEntity(cRLInfoData);
                    } catch (final PersistenceException e) {
                        logger.error("Unexpected Error while Updating the entity {}. {}", cRLInfoData.getClass(), e.getMessage());
                        systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.UPDATE_CRLSTATUS_FAILURE", ErrorSeverity.ERROR, "CRLPersistenceHelper", "Updation of CRL status to invalid",
                                "Error occured while updating the status to INVALID for CRLInfo of the CA certificate with serial number : " + cRLInfoData.getCertificateData().getSerialNumber());
                        throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", e);
                    }
                    updatedEntityCount++;
                }
            }
        }
        logger.debug("Updated CRL status to invalid for {} entities", updatedEntityCount);
    }

    /**
     * This method is used to get the crl with max crl number from a set of crls for a certificate
     *
     * @param certificateId
     *            Id of the certificate for which the crl with max crl number need to fetch.
     * @return CRLInfo
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration
     * @throws InvalidCertificateException
     *             thrown when Invalid certificate is found for entity.
     * @throws PersistenceException
     */
    public CRLInfo getCRLWithMaxCRLNumber(final long certificateId) throws CRLGenerationException, InvalidCertificateException, PersistenceException {
        final Query query = persistenceManager.getEntityManager().createQuery(getCRLWithMaxNumberQuery);
        query.setParameter("certificateId", certificateId);
        final CRLInfoData cRLInfoData = (CRLInfoData) query.getSingleResult();
        if (cRLInfoData != null) {
            return cRLInfoMapper.toAPIFromModel(cRLInfoData);
        }
        return null;
    }

    private List<CRLInfoData> getCRLDataByStatus(final CRLStatus... cRLStatus) throws CRLServiceException {
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        List<CRLInfoData> cRLDataList = null;
        parameters.put(CRL_STATUS, cRLStatus);
        try {
            cRLDataList = persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters);
        } catch (final PersistenceException e) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE);
            systemRecorder.recordError("PKI_CORE_CRL_MANAGEMENT.GET_CRL_DATA", ErrorSeverity.ERROR, "CRLPersistenceHelper", "Get CRL",
                    "Error occured while getting CRL data by status : " +Arrays.toString(cRLStatus));
            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, e);
        }
        return cRLDataList;
    }

    /**
     * @param certificateAuthority
     * @param certSerialNumber
     * @param crlInfo
     * @throws CRLServiceException
     *             thrown when internal db error occurs while updating CRLInfo
     */
    public void updateCRLInfo(final CertificateAuthority certificateAuthority, final String certSerialNumber, final CRLInfo crlInfo) throws CRLServiceException {
        try {

            final CertificateAuthorityData certificateAuthorityData = persistenceManager.findEntityByName(CertificateAuthorityData.class, certificateAuthority.getName(), NAME_PATH);

            for (final CRLInfoData crlInfoData : certificateAuthorityData.getCrlInfoDatas()) {
                if (crlInfoData.getCertificateData().getSerialNumber().equals(certSerialNumber)) {
                    if (crlInfoData.getStatus() == CRLStatus.LATEST) {
                        crlInfoData.setStatus(CRLStatus.OLD);
                        try {
                            persistenceManager.updateEntity(crlInfoData);
                        } catch (final TransactionRequiredException exception) {
                            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", exception.getMessage());
                            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", exception);
                        }
                    }
                }
            }

            persistenceManager.getEntityManager().refresh(certificateAuthorityData);
            certificateAuthorityData.getCrlInfoDatas().add(cRLInfoMapper.fromAPIToModel(crlInfo));
            persistenceManager.updateEntity(certificateAuthorityData);

        } catch (final TransactionRequiredException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", exception.getMessage());
            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", exception);
        } catch (final PersistenceException exception) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", exception.getMessage());
            throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", exception);
        }
    }

    /**
     *
     * This method will return overlapPeriod value for corresponding CrlGenerationInfo for a CRLInfo object.
     *
     * @param crlInfo
     *            CRLInfo object for which the CrlGenerationInfo need to map
     * @return String overlapPeriod value for corresponding CrlGenerationInfo for crlInfo object.
     */
    public String getOverlapPeriodForCRL(final CRLInfo crlInfo) {
        try {
            final Query query = persistenceManager.getEntityManager().createNativeQuery(getOverlapPeriodForCRLNativeQuery);
            query.setParameter("certId", crlInfo.getIssuerCertificate().getId());
            return (String) query.getSingleResult();
        } catch (final PersistenceException e) {
            logger.debug("Error occured while getting overlap period for CRL ", e);
            return null;
        }
    }
}
