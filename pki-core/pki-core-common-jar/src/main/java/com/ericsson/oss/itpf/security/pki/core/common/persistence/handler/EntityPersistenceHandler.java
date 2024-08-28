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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

public class EntityPersistenceHandler {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    Logger logger;

    @Inject
    EntityModelMapper entityModelMapper;

    private static final String updateEntityStatusToInactiveNativeQuery = "update entity_info SET status_id=3 where id not in (select distinct e_cert.entity_id from entity_certificate e_cert where e_cert.certificate_id in (select cert.id from certificate cert where cert.status_id in (1,4))) and status_id = 2";

    /**
     * Maps API model to JPA entity and persists in the database.
     * 
     * @param entityInfo
     *            object to be mapped with JPA entity and to be persisted in database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case JPA entity already exists in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void persistEntity(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        try {
            final EntityInfoData entityInfoData = entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE);

            persistenceManager.createEntity(entityInfoData);

        } catch (EntityExistsException entityExistsException) {
            logger.error("EntityInfo Already Exists {}", entityExistsException.getMessage());
            throw new CoreEntityAlreadyExistsException(EntityManagementErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entityInfo {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (PersistenceException persistenceexception) {
            logger.error("Transaction Inactive Error in creating entityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, persistenceexception);
        }
        logger.debug("Created {}", entityInfo);
    }

    /**
     * Maps API model to JPA entity and updates the same in the database.
     * 
     * @param entityInfo
     *            object to be mapped with JPA entity and to be updated in database.
     * @throws CoreEntityServiceException
     *             Thrown when any database error occurs in system.
     */
    public void updateEntity(final EntityInfo entityInfo) throws CoreEntityServiceException {

        try {
            final EntityInfoData entityInfoData = entityModelMapper.fromAPIToModel(entityInfo, OperationType.UPDATE);
            persistenceManager.updateEntity(entityInfoData);

        } catch (TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating EntityInfo {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (PersistenceException persistenceexception) {
            logger.error("Error in updating EntityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE, persistenceexception);
        }

        logger.debug("Updated {}", entityInfo);
    }

    /**
     * Get Entity Certificates and update certificate status to EXPIRED/INACTIVE into DataBase.
     * 
     * @param entityInfoData
     *            object to be used to get CertificateData
     * @param entityStatus
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void updateCertificateStatus(final EntityInfoData entityInfoData, final EntityStatus entityStatus) throws CoreEntityServiceException {

        try {
            final Set<CertificateData> certificateDatasSet = entityInfoData.getCertificateDatas();
            if (!ValidationUtils.isNullOrEmpty(certificateDatasSet)) {
                final List<CertificateData> certificateDatasList = new ArrayList<CertificateData>(certificateDatasSet);
                final CertificateData certificateData = Collections.max(certificateDatasList, new ComparatorUtil());
                if (entityStatus == EntityStatus.ACTIVE && entityInfoData.getStatus() == EntityStatus.INACTIVE && certificateData.getStatus() == CertificateStatus.INACTIVE) {
                    if (certificateData.getNotAfter().compareTo(new Date()) < 0) {
                        certificateData.setStatus(CertificateStatus.EXPIRED);
                        persistenceManager.updateEntity(certificateData);
                    }
                } else if (entityStatus == EntityStatus.INACTIVE && entityInfoData.getStatus() == EntityStatus.ACTIVE && certificateData.getStatus() == CertificateStatus.ACTIVE) {
                    certificateData.setStatus(CertificateStatus.INACTIVE);
                    persistenceManager.updateEntity(certificateData);
                }
            }
        } catch (TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in Updated Certificate Status {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
        logger.debug("Updated Certificate Status {}", entityInfoData);
    }

    /**
     * Deletes {links EntityInfo} the same in the database.
     * 
     * @param entityInfoData
     *            object to be deleted in database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void deleteEntity(final EntityInfoData entityInfoData) throws CoreEntityServiceException {

        try {
            if (entityInfoData.getStatus() == EntityStatus.NEW) {
                persistenceManager.deleteEntity(entityInfoData);
            } else if (entityInfoData.getStatus() == EntityStatus.INACTIVE) {
                entityInfoData.setStatus(EntityStatus.DELETED);
                persistenceManager.updateEntity(entityInfoData);
            }

        } catch (TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Error in updating EntityInfo {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        } catch (PersistenceException exception) {
            logger.error("Error in updating {}. {}", entityInfoData.getName(), exception.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.OCCURED_IN_DELETING + entityInfoData.getName(), exception);
        }

        logger.debug("Deleted {}", entityInfoData);
    }

    /**
     * @param entityStatus
     * @return boolean
     * @throws CoreEntityNotFoundException
     * @throws CoreEntityInUseException
     */
    public boolean checkEntityCanBeDeleted(final EntityStatus entityStatus) throws CoreEntityNotFoundException, CoreEntityInUseException {

        if (entityStatus == EntityStatus.DELETED) {

            logger.info(EntityManagementErrorCodes.ENTITY_IS_DELETED);

        } else if (entityStatus == EntityStatus.ACTIVE) {

            logger.error(EntityManagementErrorCodes.ENTITY_IS_ACTIVE);
            throw new CoreEntityInUseException(EntityManagementErrorCodes.ENTITY_IS_ACTIVE);

        } else if (entityStatus == EntityStatus.REISSUE) {

            logger.error(EntityManagementErrorCodes.ENTITY_IS_REISSUED);
            throw new CoreEntityInUseException(EntityManagementErrorCodes.ENTITY_IS_REISSUED);

        }

        return true;
    }

    /**
     * @param entityInfo
     * @return
     * @throws CoreEntityNotFoundException
     * @throws CoreEntityServiceException
     */
    public EntityInfoData getEntityInfoData(final EntityInfo entityInfo) throws CoreEntityServiceException, CoreEntityNotFoundException {

        final Map<String, Object> parameters = new HashMap<String, Object>();
        List<EntityInfoData> entityInfoDataList = null;

        final long entityId = entityInfo.getId();
        final String entityName = entityInfo.getName();
        if (entityId == 0 && ValidationUtils.isNullOrEmpty(entityName)) {

            logger.error(EntityManagementErrorCodes.ID_OR_NAME_SHOULD_PRESENT);
            throw new IllegalArgumentException(EntityManagementErrorCodes.ID_OR_NAME_SHOULD_PRESENT);

        }

        if ((entityId != 0 && !(ValidationUtils.isNullOrEmpty(entityName)))) {

            parameters.put("id", entityId);
            parameters.put("name", entityName);

        } else if (entityId != 0) {

            parameters.put("id", entityId);

        } else {

            parameters.put("name", entityName);
        }
        try {
            entityInfoDataList = persistenceManager.findEntitiesByAttributes(EntityInfoData.class, parameters);

        } catch (PersistenceException exception) {
            logger.error("Error in updating {}", exception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, exception);
        }
        if (ValidationUtils.isNullOrEmpty(entityInfoDataList)) {
            logger.error(EntityManagementErrorCodes.CA_ENTITY_NOT_FOUND);
            throw new CoreEntityNotFoundException(EntityManagementErrorCodes.CA_ENTITY_NOT_FOUND);
        } else {
            return entityInfoDataList.get(0);
        }
    }

    /**
     * Method used to persist EntityInfoData
     * 
     * @param entityInfoData
     *            object to be persisted in database.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case JPA entity already exists in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    public void persistEntityInfo(final EntityInfoData entityInfoData) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        try {
            persistenceManager.createEntity(entityInfoData);

        } catch (EntityExistsException entityExistsException) {
            logger.error("EntityInfo Already Exists {}", entityExistsException.getMessage());
            throw new CoreEntityAlreadyExistsException(EntityManagementErrorCodes.ENTITY_ALREADY_EXISTS, entityExistsException);
        } catch (TransactionRequiredException transactionRequiredException) {
            logger.error("Transaction Inactive Error in creating entityInfo {}", transactionRequiredException.getMessage());
            throw new CoreEntityServiceException(EntityManagementErrorCodes.TRANSACTION_INACTIVE, transactionRequiredException);
        }
        logger.debug("Created {}", entityInfoData);
    }

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     * 
     * @throws CoreEntityServiceException
     */

    public void updateEntityStatusToInactive() throws CoreEntityServiceException {
        int updatedEntityCount = 0;
        final Query query = persistenceManager.getEntityManager().createNativeQuery(updateEntityStatusToInactiveNativeQuery);
        try {
            updatedEntityCount = query.executeUpdate();

        } catch (PersistenceException | IllegalStateException e) {
            logger.error(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Entity status");
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_UPDATING_DATABASE + " while updating Entity status", e);
        }
        logger.info("Updated Entity status for {} entities in pki-core", updatedEntityCount);

    }
}
