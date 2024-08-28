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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl;

import javax.inject.Inject;
import javax.persistence.Entity;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.EntityValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

public class EntityManager {

    @Inject
    Logger logger;

    @Inject
    EntityPersistenceHandler entityPersistenceHandler;

    @Inject
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Inject
    EntityValidator entityValidator;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    EntityModelMapper entityMapper;

    @Inject
    private SystemRecorder systemRecorder;

    private final static String NAME_PATH = "name";

    /**
     * Validates {@link EntityInfo} object and creates it in the database.
     *
     * @param entityInfo
     *            {@link EntityInfo} object to be validated and stored in database.
     * @return EntityInfo
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case {@link EntityInfo} object already exists in database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown in case of Invalid Attribute is found in the entity.
     */
    public EntityInfo createEntity(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException {

        logger.debug("creating EntityInfo {}", entityInfo);

        final EntityInfo enInfo = validateAndCreate(entityInfo);

        logger.debug(" EntityInfo Created {}", enInfo);

        systemRecorder.recordSecurityEvent("PKICore.EntityManagement", "EntityManager", "Created entity for " + entityInfo.getName(),
                "PKICORE.CREATE_ENTITY", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return enInfo;
    }

    private EntityInfo validateAndCreate(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException {

        entityValidator.validateEntity(entityInfo, OperationType.CREATE);

        entityPersistenceHandler.persistEntity(entityInfo);
        EntityInfoData entityInfoData = null;
        try {
            entityInfoData = persistenceManager.findEntityByName(EntityInfoData.class, entityInfo.getName(), NAME_PATH);
        } catch (final PersistenceException persistenceexception) {
            logger.error("Transaction Inactive Error in retreive entityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }
        EntityInfo enInfo;
        try {
            enInfo = entityMapper.toAPIFromModel(entityInfoData);
        } catch (InvalidCRLGenerationInfoException | InvalidCertificateException e) {
            logger.debug(ErrorMessages.INTERNAL_ERROR, e);
            throw new InvalidCoreEntityAttributeException(ErrorMessages.INTERNAL_ERROR);
        }

        return enInfo;
    }

    /**
     * Validates {@link EntityInfo} object and updates it in the database.
     *
     * @param entityInfo
     *            {@link EntityInfo} object to be updated in database.
     * @return EntityInfo
     * @throws CoreEntityAlreadyExistsException
     *             Thrown if entity is already is present in database.
     * @throws CoreEntityNotFoundException
     *             Thrown in case {@link EntityInfo} object not found in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the entity.
     */
    public EntityInfo updateEntity(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, CoreEntityNotFoundException, InvalidCoreEntityAttributeException {

        logger.debug("updating EntityInfo {}", entityInfo);

        final EntityInfo enInfo = validateAndUpdate(entityInfo);

        logger.debug("EntityInfo Updated {}", enInfo);

        return enInfo;
    }

    private EntityInfo validateAndUpdate(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, CoreEntityNotFoundException,
            InvalidCoreEntityAttributeException {

        final long id = entityInfo.getId();
        EntityInfoData entityInfoData = null;
        try {
            entityInfoData = persistenceManager.findEntity(EntityInfoData.class, id);
        } catch (final PersistenceException persistenceexception) {
            logger.error("Transaction Inactive Error in retreive entityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }
        if (entityInfoData == null) {
            throw new CoreEntityNotFoundException("Entity " + EntityManagementErrorCodes.NOT_FOUND_WITH_ID + id);
        }
        entityValidator.validateEntity(entityInfo, OperationType.UPDATE);

        entityPersistenceHandler.updateEntity(entityInfo);

        EntityInfoData enInfoData;
        try {
            enInfoData = persistenceManager.findEntityByName(EntityInfoData.class, entityInfo.getName(), NAME_PATH);
        } catch (final PersistenceException persistenceexception) {
            logger.error("Transaction Inactive Error in retreive entityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }
        entityPersistenceHandler.updateCertificateStatus(enInfoData, entityInfo.getStatus());

        EntityInfo enInfo;
        try {
            enInfo = entityMapper.toAPIFromModel(enInfoData);
        } catch (InvalidCRLGenerationInfoException | InvalidCertificateException e) {
            logger.debug(ErrorMessages.INTERNAL_ERROR, e);
            throw new InvalidCoreEntityAttributeException(ErrorMessages.INTERNAL_ERROR);
        }
        return enInfo;
    }

    /**
     * This method is used for delete operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>Delete from DB if is not being used any other JPA Entities.</li>
     * <li>Form the Response Object and return.</li>
     * </ul>
     *
     * @param entityInfo
     *            {@link Entity} that is to be deleted.
     * @throws CoreEntityInUseException
     *             thrown when deleting an entity that has active certificates.
     * @throws CoreEntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws CoreEntityServiceException
     *             Thrown when internal db error occurs while deleting entity.
     *
     */
    public void deleteEntity(final EntityInfo entityInfo) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException {

        logger.debug("Deleting EntityInfo {}", entityInfo);

        validateAndDelete(entityInfo);

        logger.debug("EntityInfo Deleted {}", entityInfo);

        systemRecorder.recordSecurityEvent("PKICore.EntityManagement", "EntityManager", "Deleted entity for " + entityInfo.getName(),
                "PKICORE.DELETE_ENTITY", ErrorSeverity.INFORMATIONAL, "SUCCESS");

    }

    private void validateAndDelete(final EntityInfo entityInfo) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException {

        if (entityInfo.getName() != null) {
            final String trimmedName = entityInfo.getName().trim();
            entityInfo.setName(trimmedName);

            entityValidator.checkEntityNameFormat(trimmedName);
        }

        final EntityInfoData entityInfoData = entityPersistenceHandler.getEntityInfoData(entityInfo);
        final EntityStatus entityStatus = entityInfoData.getStatus();

        try {
            if (entityValidator.checkEntityCanBeDeleted(entityStatus)) {
                entityPersistenceHandler.deleteEntity(entityInfoData);
            }
        } catch (final PersistenceException persistenceException) {
            logger.debug(EntityManagementErrorCodes.UNEXPECTED_ERROR, persistenceException);
            logger.error(EntityManagementErrorCodes.UNEXPECTED_ERROR);
            throw new CoreEntityServiceException(EntityManagementErrorCodes.UNEXPECTED_ERROR);
        }
    }

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     *
     * @throws CoreEntityServiceException
     */

    public void updateEntityStatusToInactive() throws CoreEntityServiceException {
        entityPersistenceHandler.updateEntityStatusToInactive();
        caEntityPersistenceHandler.updateCAEntityStatusToInactive();
    }

}
