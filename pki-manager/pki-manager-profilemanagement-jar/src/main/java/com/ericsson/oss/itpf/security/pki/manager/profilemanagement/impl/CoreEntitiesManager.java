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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl;

import java.util.ArrayList;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;


import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.eservice.ProflieManagementEserviceProxy;

/**
 * This class contains basic methods for CUD operations towards pki core. List of methods implemented here are:
 * <ul>
 * <li>Creating entity</li>
 * <li>Updating entity</li>
 * <li>Deleting entity</li>
 * </ul>
 *
 */
public class CoreEntitiesManager {

    @Inject
    protected Logger logger;

    @Inject
    ProflieManagementEserviceProxy proflieManagementEserviceProxy;

    /**
     *
     * API for creating an entity of any type
     *
     * @param entity
     *            {@link Entity} instance that is to be created.
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public <T extends AbstractEntity> void createEntity(final T entity) throws EntityAlreadyExistsException, EntityServiceException, InvalidEntityAttributeException {
        final String entityName = getEntityName(entity);

        try {
            switch (entity.getType()) {
            case CA_ENTITY:
                final CAEntity caEntity = (CAEntity) entity;
                proflieManagementEserviceProxy.getCaEntityManagementService().createCA(caEntity.getCertificateAuthority());
                break;
            case ENTITY:
                final Entity endEntity = (Entity) entity;
                proflieManagementEserviceProxy.getEntityManagementService().createEntity(endEntity.getEntityInfo());
                break;

            default:
                logger.error("Creation of entity {} in pki core failed due to invalid entity type {}", entityName, entity.getType());
            }
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException entityAlreadyExistsException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_CREATION_ENTITY, entityName, entityAlreadyExistsException);
            logger.error("Error occured during creation of entity {} in pkicore", entityName);
            throw new EntityAlreadyExistsException(entityAlreadyExistsException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException invalidEntityAttributeException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_CREATION_ENTITY, entityName, invalidEntityAttributeException);
            logger.error("Error occured during creation of entity {} in pkicore", entityName);
            throw new InvalidEntityAttributeException(invalidEntityAttributeException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException entityServiceException) {
            logger.error("Error occured during creation of entity {} in pkicore", entityName);
            throw new EntityServiceException(entityServiceException.getMessage(), entityServiceException);
        }

        logger.debug("Successfully created entity {} in pki-core", entityName);
    }

    /**
     * API for updating an entity based on Id/Name.
     *
     * @param entity
     *            {@link Entity} instance that is to be created.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity is invalid.
     */
    public <T extends AbstractEntity> void updateEntity(final T entity) throws EntityAlreadyExistsException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        final String entityName = getEntityName(entity);

        try {
            switch (entity.getType()) {
            case CA_ENTITY:
                final CAEntity caEntity = (CAEntity) entity;
                proflieManagementEserviceProxy.getCaEntityManagementService().updateCA(caEntity.getCertificateAuthority());
                break;
            case ENTITY:
                final Entity endEntity = (Entity) entity;
                proflieManagementEserviceProxy.getEntityManagementService().updateEntity(endEntity.getEntityInfo());
                break;
            default:
                logger.error("Updation of entity {} in pki core failed due to invalid entity type {}", entityName, entity.getType());
            }
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_UPDATION_ENTITY, entityName, entityNotFoundException);
            logger.error("Error occured during updation of entity {} in pkicore", entityName);
            throw new EntityNotFoundException(entityNotFoundException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException entityAlreadyExistsException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_UPDATION_ENTITY, entityName, entityAlreadyExistsException);
            logger.error("Error occured during updation of entity {} in pkicore", entityName);
            throw new EntityAlreadyExistsException(entityAlreadyExistsException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException invalidEntityAttributeException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_CREATION_ENTITY, entityName, invalidEntityAttributeException);
            logger.error("Error occured during creation of entity {} in pkicore", entityName);
            throw new InvalidEntityAttributeException(invalidEntityAttributeException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException entityServiceException) {
            logger.error("Error occured during updation of entity {} in pkicore", entityName);
            throw new EntityServiceException(entityServiceException.getMessage(), entityServiceException);
        }

        logger.debug("Successfully updated entity {} in pki-core", entityName);
    }

    /**
     * API for deleting an entity based on Id/Name.
     *
     * @param entity
     *            instance {@link Entity} with Id/name set.
     * @return Instance of {@link ProfileManagerResponse} with status of operation set.
     *
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any profile or is having any ongoing operation.
     * @throws EntityNotFoundException
     *             thrown when entity do not exists in DB.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    public <T extends AbstractEntity> void deleteEntity(final T entity) throws EntityInUseException, EntityNotFoundException, EntityServiceException {
        final String entityName = getEntityName(entity);

        try {
            switch (entity.getType()) {
            case CA_ENTITY:
                final CAEntity caEntity = (CAEntity) entity;
                proflieManagementEserviceProxy.getCaEntityManagementService().deleteCA(caEntity.getCertificateAuthority());
                break;
            case ENTITY:
                final Entity endEntity = (Entity) entity;
                proflieManagementEserviceProxy.getEntityManagementService().deleteEntity(endEntity.getEntityInfo());
                break;

            default:
                logger.error("deletion of entity {} in pki core failed due to invalid entity type {}", entityName, entity.getType());
            }
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_DELETION_ENTITY, entityName, entityNotFoundException);
            logger.error("Error occured during deletion of entity {} in pkicore", entityName);
            throw new EntityNotFoundException(entityNotFoundException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityInUseException entityInUseException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_DELETION_ENTITY, entityName, entityInUseException);
            logger.error("Error occured during deletion of entity {} in pkicore", entityName);
            throw new EntityInUseException(entityInUseException.getCause());
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException entityServiceException) {
            logger.debug(ProfileServiceErrorCodes.ERROR_OCCURED_DELETION_ENTITY, entityName, entityServiceException);
            logger.error("Error occured during deletion of entity {} in pkicore", entityName);
            throw new EntityServiceException(entityServiceException.getCause());
        }

        logger.debug("Successfully deleted entity {} in pki-core", entityName);
    }

    /**
     * Method used to validate and create EntityInfo/CertificateAuthority
     *
     * @param entities
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T extends AbstractEntity> void createBulkEntities(final List<T> entities) throws EntityAlreadyExistsException, EntityServiceException {

        final List<CertificateAuthority> certificateAuthorities = new ArrayList<CertificateAuthority>();
        final List<EntityInfo> entitiesInfo = new ArrayList<EntityInfo>();

        for (final T entity : entities) {
            if (entity.getType() == EntityType.ENTITY) {
                entitiesInfo.add(((Entity) entity).getEntityInfo());
            } else {
                certificateAuthorities.add(((CAEntity) entity).getCertificateAuthority());
            }
        }

        try {
            if (certificateAuthorities.size() != 0) {
                proflieManagementEserviceProxy.getCaEntityManagementService().importCAEntities(certificateAuthorities);
            }
            if (entitiesInfo.size() != 0) {
                proflieManagementEserviceProxy.getEntityManagementService().importEntities(entitiesInfo);
            }
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException entityAlreadyExistsException) {
            logger.error("Error occured during creation of entity in pkicore");
            throw new EntityAlreadyExistsException(entityAlreadyExistsException);

        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException entityServiceException) {
            logger.error("Error occured during creation of entity in pkicore");
            throw new EntityServiceException(entityServiceException);
        }

    }

    private <T extends AbstractEntity> String getEntityName(final T entity) {
        String entityName = "";
        switch (entity.getType()) {
        case CA_ENTITY:
            final CAEntity caEntity = (CAEntity) entity;
            entityName = caEntity.getCertificateAuthority().getName();
            break;

        case ENTITY:
            final Entity endEntity = (Entity) entity;
            entityName = endEntity.getEntityInfo().getName();
            break;
        }
        return entityName;
    }
}
