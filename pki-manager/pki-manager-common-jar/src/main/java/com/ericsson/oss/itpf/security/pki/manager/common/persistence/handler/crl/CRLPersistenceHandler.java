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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Query;
import javax.persistence.TransactionRequiredException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CRLInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * CRLPersistenceHandler is a helper class for handling CRUD operations of CRL.
 *
 * @author xbensar
 */
public class CRLPersistenceHandler

{
    private static final String CA_ENTITY_NOT_FOUND = "CA Entity Not Found";

    private static final String fetchDuplicateCrlNativeQuery = "SELECT ca.name, c.serial_number FROM caentity ca JOIN ca_certificate cc ON ca.id = cc.ca_id JOIN certificate c ON cc.certificate_id = c.id where ca.is_external_ca = 'false' and c.id in (SELECT certificate_id FROM crlinfo  GROUP BY certificate_id HAVING COUNT(*) > 1)";
    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    private CAEntityMapper caEntityMapper;

    @Inject
    private CRLInfoMapper crlInfoMapper;

    @Inject
    private PersistenceManager persistenceManager;

    @Inject
    private Logger logger;

    @Inject
    CAEntityData caEntityData;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityPersistenceHandler<CAEntity> caEntityPersistenceHandler;

    @Inject
    private SystemRecorder systemRecorder;

    private static final String CRL_STATUS = "status";
    private static final String PUBLISHED_TO_CDPS = "publishedToCdps";
    private static final String fetchCANameForCRLNativeQuery = "SELECT name FROM caentity ca JOIN ca_crlinfo cc ON ca.id=cc.ca_id WHERE crlinfo_id=(:crlInfoId)";
    private static final String getOverlapPeriodForCRLNativeQuery = "SELECT overlap_period FROM crl_generation_info WHERE id =( SELECT crl_generation_info_id FROM crl_generation_info_ca_certificate WHERE certificate_id= :certId)";
    private static final String activeAndInactiveCAEntitiesQuery = " SELECT ca from CAEntityData ca where ca.externalCA='false' and ca.certificateAuthorityData.status in (2,3)";

    /**
     * Gets CAEntity for the given caname.
     *
     * @param caEntityName
     *            The CAEntity name.
     * @return caEntityData
     * @throws CAEntityNotInternalException
     *             thrown when given CA Entity exists but it's an external CA.
     * @throws CANotFoundException
     *             Thrown if the given CAEntity not found in the database.
     * @throws CRLServiceException
     *             Thrown in case of any problem occurs while doing database operations.
     * @throws InvalidEntityAttributeException
     *             thrown when invalid entity attribute is provided as part of the request.
     */
    public CAEntity getCAEntity(final String caEntityName) throws CAEntityNotInternalException, CANotFoundException, CRLServiceException, InvalidEntityAttributeException {
        logger.info("Fetching the CA Entity :[{}] ", caEntityName);
        try {
            final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, caEntityName, Constants.CA_NAME_PATH);

            if (caEntityData == null) {
                logger.error("CAEntity {}  not found", caEntityName);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CA_ENTITY_NOT_FOUND", ErrorSeverity.ERROR, "CRLPersistenceHandler", "Generate/Get CRL", "CA Entity Not Found: " + caEntityName);
                throw new CANotFoundException(CA_ENTITY_NOT_FOUND + caEntityName);
            }
            return caEntityMapper.toAPIFromModel(caEntityData);
        } catch (final PersistenceException p) {
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLPersistenceHandler", "Generate/Get CRL", "Error while fetching CA: " + caEntityName);
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR, p);
        }
    }

    /**
     * This Method gets the CRL Information from DB using CACertificateIdentifier object and using this CRL Information Update CRL Status in DB
     *
     * @param crlInfo
     *            it holds the CAName and Certificate Serial Number,CRL and thisUpdate
     *
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     */
    public void updateCRLStatus(final CRLInfo crlInfo) throws CRLServiceException {
        try {
            final CRLInfoData crlInfoData = crlInfoMapper.fromAPIToModel(crlInfo, OperationType.UPDATE);
            persistenceManager.updateEntity(crlInfoData);
        } catch (final PersistenceException persistenceException) {
            throw new CRLServiceException(persistenceException);
        }
    }

    /**
     * This method will update CRL status to EXPIRED for all crls whose validity has expired.
     *
     * @throws CRLServiceException
     *             Thrown when update entity failed.
     */
    public List<CACertificateIdentifier> updateCRLStatusToExpired() throws CRLServiceException, InvalidCRLGenerationInfoException {
        logger.debug("Updating the CRL status to expired in pki-manager");
        final Set<CACertificateIdentifier> caCertificateIdentifierSet = new HashSet<CACertificateIdentifier>();

        int updatedEntityCount = 0;
        final List<CRLInfo> crlInfoList = getCRLInfoByStatus(CRLStatus.LATEST);
        if (crlInfoList != null) {
            for (final CRLInfo crlInfo : crlInfoList) {
                if (crlInfo.getNextUpdate().compareTo(new Date()) <= 0) {
                    crlInfo.setStatus(CRLStatus.EXPIRED);
                    try {
                        persistenceManager.updateEntity(crlInfoMapper.fromAPIToModel(crlInfo, OperationType.UPDATE));
                        caCertificateIdentifierSet.add(getCACertificateIdentifierByCRL(crlInfo));
                    } catch (final PersistenceException e) {
                        logger.error("Unexpected Error while Updating the entity {}. {}", crlInfo.getClass(), e.getMessage());
                        throw new CRLServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating CRL status", e);
                    }
                    updatedEntityCount++;
                }
            }
        }
        logger.debug("Updated CRL status to expired for {} entities", updatedEntityCount);
        return new ArrayList<CACertificateIdentifier>(caCertificateIdentifierSet);
    }

    /**
     * This method will prepare and return a CACertificateIdentifier object using passed CRLInfo object.
     *
     * @param crlInfo
     * @return CACertificateIdentifier
     */
    public CACertificateIdentifier getCACertificateIdentifierByCRL(final CRLInfo crlInfo) {
        return new CACertificateIdentifier(getCANameByCRL(crlInfo.getId()), crlInfo.getIssuerCertificate().getSerialNumber());
    }

    /**
     * This method will return the name of the CertificateAuthority which owns the crlInfo object.
     *
     * @param crlInfoId
     *            id of the CRLInfo object for which the corresponding ca name need to find.
     * @return caName name of the CertificateAuthority which owns the crlInfo object
     */
    public String getCANameByCRL(final long crlInfoId) throws PersistenceException {
        final Query query = persistenceManager.getEntityManager().createNativeQuery(fetchCANameForCRLNativeQuery);
        query.setParameter("crlInfoId", crlInfoId);
        final String caName = (String) query.getSingleResult();
        return caName;
    }

    /**
     * This method will update or persist the CrlInfo for the certificate whose info is passed by CACertificateIdentifier.
     *
     * @param caCrlInfoHashMapToUpdate
     * @param caCrlInfoHashMapToSet
     *
     */
    public void updateLatestCRL(final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToUpdate, final Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet) {
        logger.debug("Updating latest CRL in pki-manager");
        for (final CACertificateIdentifier caCertId : caCrlInfoHashMapToUpdate.keySet()) {
            try {
                if (caCrlInfoHashMapToUpdate.get(caCertId) != null) {
                    updateOldCRLInfo(caCrlInfoHashMapToUpdate.get(caCertId), caCrlInfoHashMapToSet.get(caCertId));
                } else {
                    saveNewCRLInfo(caCertId, caCrlInfoHashMapToSet.get(caCertId));
                }
            } catch (final PersistenceException e) {
                logger.debug(ErrorMessages.UPDATE_LATEST_CRL_FAILED, e);
                systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERANL_ERROR", ErrorSeverity.ERROR, "CRLPersistenceHandler", "CRL Generation", ErrorMessages.UPDATE_LATEST_CRL_FAILED
                        + " for CA Certificate " + caCertId);
                logger.error(ErrorMessages.UPDATE_LATEST_CRL_FAILED, "for CA Certificate {} ,{}", caCertId, e.getMessage());
            }
        }
        logger.debug("Latest CRLs updated in pki-manager");
    }

    private void updateOldCRLInfo(final CRLInfo crlInfoToUpdate, final CRLInfo crlInfoToSet) throws PersistenceException {
        if (crlInfoToSet != null) {
            crlInfoToUpdate.setCrlNumber(crlInfoToSet.getCrlNumber());
            crlInfoToUpdate.setNextUpdate(crlInfoToSet.getNextUpdate());
            crlInfoToUpdate.setThisUpdate(crlInfoToSet.getThisUpdate());
            crlInfoToUpdate.setPublishedToCDPS(crlInfoToSet.isPublishedToCDPS());
            crlInfoToUpdate.setStatus(crlInfoToSet.getStatus());
            crlInfoToUpdate.getCrl().setX509CRLHolder(crlInfoToSet.getCrl().getX509CRLHolder());
            persistenceManager.updateEntity(crlInfoMapper.fromAPIToModel(crlInfoToUpdate, OperationType.UPDATE));
        }
    }

    private void saveNewCRLInfo(final CACertificateIdentifier caCertId, final CRLInfo crlInfoToSave) throws PersistenceException {
        final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, caCertId.getCaName(), Constants.CA_NAME_PATH);
        for (final CertificateData certificateData : caEntityData.getCertificateAuthorityData().getCertificateDatas()) {
            if (certificateData.getSerialNumber().equals(caCertId.getCerficateSerialNumber())) {
                if (crlInfoToSave != null) {
                    crlInfoToSave.getIssuerCertificate().setId(certificateData.getId());
                    final CRLInfoData crlInfoData = crlInfoMapper.fromAPIToModel(crlInfoToSave, OperationType.CREATE);
                    persistenceManager.refresh(caEntityData);
                    caEntityData.getCertificateAuthorityData().getcRLDatas().add(crlInfoData);
                    persistenceManager.updateEntity(caEntityData);
                    break;
                } else {
                    logger.error(ErrorMessages.CRL_NOT_FOUND, " for certificate {} for the CA {}.", caCertId.getCerficateSerialNumber(), caCertId.getCaName());
                    systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.CRL_NOT_FOUND", ErrorSeverity.ERROR, "CRLPersistenceHandler", "CRL", ErrorMessages.CRL_NOT_FOUND + " for the CA {}"
                            + caCertId);
                }
            }
        }
    }

    /**
     * This method will return list of CRLInfo whose status are crlStatus
     *
     * @param crlStatus
     * @return list of CRLInfo
     * @throws CRLServiceException
     *             Thrown when there is any internal error like database error during the fetching the CRL
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CRLInfo> getCRLInfoByStatus(final CRLStatus... crlStatus) throws CRLServiceException, InvalidCRLGenerationInfoException {
        List<CRLInfoData> crlInfoDataList = new ArrayList<CRLInfoData>();
        final List<CRLInfo> crlInfoList = new ArrayList<CRLInfo>();
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put(CRL_STATUS, crlStatus);
        try {
            crlInfoDataList = persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters);
        } catch (final PersistenceException e) {
            logger.error("Exception occured while fetching the CRLInfo by status");
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLPersistenceHandler", "Unpublish CRL From CDPS",
                    "Exception occured while fetching the CRLInfo by status");
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR + e.getMessage(), e);
        }
        if (!crlInfoDataList.isEmpty()) {
            for (final CRLInfoData crlInfodata : crlInfoDataList) {
                crlInfoList.add(crlInfoMapper.toAPIFromModel(crlInfodata));
            }
            return crlInfoList;
        }
        return null;
    }

    /**
     * This method will return list of CRLInfo get isPublishedToCdps flag
     *
     * @param isPublishedToCdps
     * @return - list of CRL
     * @throws CRLServiceException
     *             - thrown when there is any database error during the generation and fetching of CRL.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CRLInfo> getAllCRLInfoByPublishedToCDPS(final boolean isPublishedToCdps) throws CRLServiceException, InvalidCRLGenerationInfoException {
        final HashMap<String, Object> criteriaMap = new HashMap<String, Object>();
        criteriaMap.put(PUBLISHED_TO_CDPS, isPublishedToCdps);

        final List<CRLInfo> crlInfoList = getCRLInfoList(criteriaMap);
        return crlInfoList;
    }

    /**
     * This method will return overlapPeriod value for corresponding CrlGenerationInfo for a CRLInfo object.
     *
     * @param crlInfo
     *            CRLInfo object for which the CrlGenerationInfo need to map
     * @return String overlapPeriod value for corresponding CrlGenerationInfo for crlInfo object.
     * @throws PersistenceException
     */
    public String getOverlapPeriodForCRL(final CRLInfo crlInfo) throws PersistenceException {
        final Query query = persistenceManager.getEntityManager().createNativeQuery(getOverlapPeriodForCRLNativeQuery);
        query.setParameter("certId", crlInfo.getIssuerCertificate().getId());
        return (String) query.getSingleResult();
    }

    /**
     * This method will find and return list CRLInfo objects which are need to be published to CDPS service. The CRLInfo object should have status latest ,published_to_cdps false and corresponding CA
     * should have flag publish_to_cdps as true.
     *
     * @return List<CRLInfo>
     * @throws CRLServiceException
     *             Thrown when there is any database error during the generation and fetching of CRL.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CRLInfo> getCRLsToPublishToCDPS() throws CRLServiceException, InvalidCRLGenerationInfoException {
        final HashMap<String, Object> criteriaMap = new HashMap<String, Object>();
        criteriaMap.put(CRL_STATUS, CRLStatus.LATEST.getId());
        criteriaMap.put(PUBLISHED_TO_CDPS, false);

        // TODO Check if corresponding CertificateAuthority has value true for publishedToCDPS column.
        final List<CRLInfo> crlInfoList = getCRLInfoList(criteriaMap);
        return crlInfoList;
    }

    /**
     * This method updates the CAEntity data in DB
     *
     * @param caEntity
     *
     * @param publishToCDPS
     *            represents the status of the CRL publish to CDPS and which need to be updated in caEntity object.
     * @throws CRLServiceException
     *             Thrown when there are any DB Errors while persisting.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     */
    public void updateCAEnity(final CAEntity caEntity, final boolean publishToCDPS) throws CRLServiceException, EntityNotFoundException {
        try {
            final CAEntityData caEntityData = caEntityMapper.fromAPIToModel(caEntity);
            caEntityData.getCertificateAuthorityData().setPublishToCDPS(publishToCDPS);
            final CAEntityData sourceCAEntityData = (CAEntityData) caEntityPersistenceHandler.findAndMergeEntityData(caEntityData);
            persistenceManager.updateEntity(sourceCAEntityData);
        } catch (final PersistenceException | EntityServiceException | ProfileServiceException e) {
            logger.error("Exception occured while updating the CAEntity");
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLPersistenceHandler", "Publish CRL to CDPS",
                    "Exception occured while updating the CAEntity " + caEntity);
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR, e);
        }
    }

    /**
     * This method will get CRLinfo List
     *
     * @param criteriaMap
     *            - MAP<String,Object>
     * @return - CRLinfo List
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown for invalid CRLGenerationInfo or invalid fields in CRLGenerationInfo.
     */
    public List<CRLInfo> getCRLInfoList(final Map<String, Object> criteriaMap) throws CRLServiceException, InvalidCRLGenerationInfoException {
        List<CRLInfoData> crlInfoDataList = new ArrayList<CRLInfoData>();

        try {
            crlInfoDataList = persistenceManager.findEntitiesByAttributes(CRLInfoData.class, criteriaMap);
        } catch (final PersistenceException persistenceException) {
            logger.error("Exception occured while fetching the CRLInfo by status");
            systemRecorder.recordError("PKIMANAGER_CRL_MANAGEMENT.INTERNAL_ERROR", ErrorSeverity.ERROR, "CRLPersistenceHandler", "Publish CRL to CDPS",
                    "Exception occured while fetching the CRLInfo by status");
            throw new CRLServiceException(ErrorMessages.INTERNAL_ERROR + ": Unable to fetch the CRLInfo by status ", persistenceException);
        }

        final List<CRLInfo> crlInfoList = crlInfoMapper.toAPIFromModel(crlInfoDataList);
        return crlInfoList;
    }

    /**
     * This method will hard delete the crls from the pki-manager data base.
     *
     * @param caCertificateIdentifiers
     *            List of CACertificateIdentifier objects whose CRLs need to remove from pki-manager data base.
     * @throws CRLServiceException
     *             thrown database errors occurred while fetching of CRL.
     * @throws CANotFoundException
     *             Thrown when ca entity does not Exists.
     */
    public void deleteInvalidCRLs(final List<CACertificateIdentifier> caCertificateIdentifiers) throws CANotFoundException, CRLServiceException {
        if (caCertificateIdentifiers != null && !caCertificateIdentifiers.isEmpty()) {
            for (final CACertificateIdentifier caCertificateIdentifier : caCertificateIdentifiers) {
                try {
                    final CAEntityData caEntityData = persistenceManager.findEntityByName(CAEntityData.class, caCertificateIdentifier.getCaName(), Constants.CA_NAME_PATH);
                    deleteCRLInfo(caEntityData, caCertificateIdentifier.getCerficateSerialNumber());

                } catch (final PersistenceException exception) {
                    logger.error(CA_ENTITY_NOT_FOUND);
                    throw new CANotFoundException(CA_ENTITY_NOT_FOUND, exception);
                }
            }
        }
    }

    private void deleteCRLInfo(final CAEntityData caEntityData, final String certSerialNo) throws CANotFoundException, CRLServiceException {
        try {
            persistenceManager.refresh(caEntityData);
        } catch (final javax.persistence.EntityNotFoundException exception) {
            logger.error(CA_ENTITY_NOT_FOUND);
            throw new CANotFoundException(CA_ENTITY_NOT_FOUND, exception);
        } catch (final TransactionRequiredException exception) {
            logger.error(ErrorMessages.TRANSACTION_INACTIVE);
            throw new CRLServiceException(ErrorMessages.TRANSACTION_INACTIVE, exception);
        }

        final Set<CRLInfoData> crlInfoDatas = caEntityData.getCertificateAuthorityData().getcRLDatas();
        if (!(ValidationUtils.isNullOrEmpty(crlInfoDatas))) {
            final Set<CRLInfoData> crlsToBeRemoved = new HashSet<CRLInfoData>();
            for (final CRLInfoData crlInfoData : crlInfoDatas) {
                if (crlInfoData.getCertificateData().getSerialNumber().equals(certSerialNo)) {
                    crlsToBeRemoved.add(crlInfoData);
                }
            }
            caEntityData.getCertificateAuthorityData().getcRLDatas().removeAll(crlsToBeRemoved);
            persistenceManager.updateEntity(caEntityData);
        }
    }

    /**
     * This method will prepare list of CACertificateIdentifier's based on duplicate records in crlinfo table.
     * 
     * @return CACertificateIdentifier list List of CACertificateIdentifier objects whose duplicate records need to be removed from pki-manager data base.
     */
    public List<CACertificateIdentifier> getRequiredCACertIds() {
        logger.debug("Inside getRequiredCACertIds method ");
        final List<CACertificateIdentifier> caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        final Query query = persistenceManager.getEntityManager().createNativeQuery(fetchDuplicateCrlNativeQuery);
        final List<Object[]> resultSet = query.getResultList();
        if (!resultSet.isEmpty()) {
            for (final Object[] result : resultSet) {
                final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
                caCertificateIdentifier.setCaName((String) result[0]);
                caCertificateIdentifier.setCerficateSerialNumber((String) result[1]);
                caCertificateIdentifierList.add(caCertificateIdentifier);
            }
        }
        logger.info("Duplicate records CACertificateIdentifier List size is [{}]", caCertificateIdentifierList.size());
        logger.debug("End Of getRequiredCACertIds method ");
        return caCertificateIdentifierList;
    }

    /**
     * This method is a helper method for getLatestCRLs in CRLManager. This method will return a map of all valid CACertificateIdentifiers and their corresponding CRLInfos.
     * 
     * @return Map of CACertitificateIdentifier and its CRLInfo.
     */
    public Map<CACertificateIdentifier, CRLInfo> getCACertCRLInfoMap() {
        logger.debug("Entering method getCACertCRLInfoMap in CRLPersistenceHandler class");
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = new HashMap<CACertificateIdentifier, CRLInfo>();
        final Query query = persistenceManager.getEntityManager().createQuery(activeAndInactiveCAEntitiesQuery);
        final List<CAEntityData> caEntites = query.getResultList();
        for (final CAEntityData caEntityData : caEntites) {
            final String caName = caEntityData.getCertificateAuthorityData().getName();
            for (CertificateData certficateData : caEntityData.getCertificateAuthorityData().getCertificateDatas()) {
                final boolean isValidCert = isValidCertificate(certficateData);
                if (isValidCert) {
                    final CACertificateIdentifier caCertId = new CACertificateIdentifier(caName, certficateData.getSerialNumber());
                    if (!(ValidationUtils.isNullOrEmpty(caEntityData.getCertificateAuthorityData().getCrlGenerationInfo()))) {
                        final Set<CRLInfoData> crlInfoDataSet = caEntityData.getCertificateAuthorityData().getcRLDatas();
                        if (ValidationUtils.isNullOrEmpty(crlInfoDataSet)) {
                            caCertCRLInfoMap.put(caCertId, null);
                        } else {
                            for (CRLInfoData crlInfoData : crlInfoDataSet) {
                                if (crlInfoData.getCertificateData().getId() == certficateData.getId()) {
                                    final CRLInfo crlInfo = crlInfoMapper.toAPIFromModel(crlInfoData);
                                    caCertCRLInfoMap.put(caCertId, crlInfo);
                                }
                            }
                        }
                    } else {
                        final String cRLGenerationInfomsg = String.format(ErrorMessages.UNABLE_TO_FETCH_LATEST_CRL, caName, "the CA doesn't have CRLGenerationInfo.");
                        logger.info(cRLGenerationInfomsg);
                    }
                }
            }
        }
        logger.debug("End of method getCACertCRLInfoMap in CRLPersistenceHandler class");
        return caCertCRLInfoMap;
    }

    private boolean isValidCertificate(final CertificateData certficateData) {
        if (certficateData.getStatus().intValue() == CertificateStatus.REVOKED.getId() || (certficateData.getNotAfter().before(new Date()))) {
            return false;
        }
        if (certficateData.getIssuerCertificate() != null) {
            return (isValidCertificate(certficateData.getIssuerCertificate()));
        }
        return true;
    }
}
