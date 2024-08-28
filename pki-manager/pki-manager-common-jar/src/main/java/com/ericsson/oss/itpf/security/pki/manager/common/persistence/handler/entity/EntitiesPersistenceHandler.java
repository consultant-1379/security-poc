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

package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import java.util.List;
import java.util.Map;

import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyDeletedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AbstractEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * This class is responsible for DB CRUD Operation. Each method is responsible for
 * <ul>
 * <li>Mapping API Model to JPA Entity</li>
 * <li>Do CRUD Operation on JPA Entity</li>
 * <li>Convert back to API Model if required</li>
 * </ul>
 *
 * @param <T>
 *            Class extending {@link AbstractEntity} i.e., {@link CAEntity} / {@link Entity}.
 */
public interface EntitiesPersistenceHandler<T extends AbstractEntity> {

    /**
     * This method is used for create operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Persist into DB.</li>
     * <li>Retrieve created Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} that is to be persisted.
     * @return {@link CAEntity}/ {@link Entity} that is persisted successfully.
     *
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity Type is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity is invalid.
     */
    T createEntity(T entity) throws EntityAlreadyExistsException, EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException,InvalidProfileAttributeException;


    /**
     * This method is used for update operation. It Does the following operation:
     * <ul>
     * <li>Map Validated API Model to JPA Entity.</li>
     * <li>Update in DB.</li>
     * <li>Retrieve updated Entity and Map back to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} that is to be updated.
     *
     * @return {@link CAEntity}/ {@link Entity} that is updated successfully.
     *
     * @throws EntityNotFoundException
     *             thrown when given {@link Entity} doesn't exists in DB to update.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    <E extends AbstractEntityData> T updateEntity(T entity) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
    InvalidEntityAttributeException;

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} with Id/name Set.
     *
     * @return {@link CAEntity}/ {@link Entity} that is retrieved successfully.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown when name or id passed are invalid.
     */
    T getEntity(T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * This method retrieves entity which is used for update entity operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} with Id/name Set.
     * @return {@link CAEntity}/ {@link Entity} that is retrieved successfully.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown when name or id passed are invalid.
     */
    T getEntityForImport(T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * This method verifies whether entity can be deleted or not
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity}.
     *
     * @return <code>true</code> or <code>false</code>
     *
     * @throws EntityAlreadyDeletedException
     *             thrown when the given entity is already in deleted state.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any profile or is having any ongoing operation.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity is invalid.
     */
    boolean isDeletable(T entity) throws EntityAlreadyDeletedException, EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException;

    /**
     * This method is used for delete operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>Delete from DB if is not being used any other JPA Entities.</li>
     * <li>Form the Response Object and return.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} that is to be deleted.
     *
     * @return {@link ProfileManagerResponse} with status messages set.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any profile or is having any ongoing operation.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity is invalid.
     */
    void deleteEntity(T entity) throws EntityNotFoundException, EntityServiceException, EntityInUseException, InvalidEntityAttributeException;

    /**
     * This method is used for bulk retrieving operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return Instance of {@link Entities} containing {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    Entities getEntities(EntityType entityType) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException;

    /**
     * This method is used for retrieving Entities in bulk used for import entities operation. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances based on Class Type.</li>
     * <li>Map all the JPA Entities retrieved to API Models.</li>
     * </ul>
     *
     * @return Instance of {@link Entities} containing {@link java.util.List} of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    Entities getEntitiesForImport(EntityType entityType)
            throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException;

    /**
     * This method is used for retrieve operation by Name. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param name
     *            name of entity to be retrieved.
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @param namePath
     *            Path of Field name in JPA Entity separated by '.'
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    <E> E getEntityByName(String name, Class<E> entityClass, String namePath) throws EntityNotFoundException, EntityServiceException;

    /**
     * This method is used for retrieve operation by Id. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param id
     *            id of entity to be retrieved.
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     *
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    <E> E getEntityById(long id, Class<E> entityClass) throws EntityNotFoundException, EntityServiceException;

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>retrieve JPA Entity from DB.</li>
     * </ul>
     *
     * @param entityClass
     *            class of {@link CAEntityData}/{@link EntityData}
     *
     * @param input
     *            {@link java.util.Map} containing attribute and its value that are to be used in WHERE condition in query.
     *
     * @return {@link CAEntityData}/ {@link EntityData} that is retrieved successfully.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    <E> E getEntityWhere(Class<E> entityClass, Map<String, Object> inputs) throws EntityServiceException;

    /**
     * This method is used check the availability of Name used for {@link CAEntity}/ {@link Entity}
     *
     * @param name
     *            name of entity to be checked
     * @return <code>true</code> or <code>false</code>
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     *
     */
    boolean isNameAvailable(String name) throws EntityServiceException;

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} with Id/name Set.
     * @param isIssuerDataRequired
     *         if false the issuer certificates data is not retrieved
     * @return {@link CAEntity}/ {@link Entity} that is retrieved successfully.
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category is not found in the system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity Type is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             Thrown when Invalid Attribute is found while mapping Entity.
     * @throws InvalidEntityCategoryException
     *             Thrown when the given Entity category is invalid.
     */
    List<T> getEntitiesByCategory(EntityCategory entityCategory, Boolean isIssuerDataRequired) throws EntityCategoryNotFoundException,
            EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException,
    InvalidEntityCategoryException;

    /**
     * This method is used for retrieve operation. It Does the following operation:
     * <ul>
     * <li>Get the API Model with Id/Name set.</li>
     * <li>retrieve JPA Entity from DB.</li>
     * <li>Map JPA Entity to API Model.</li>
     * </ul>
     *
     * @param entity
     *            {@link CAEntity}/ {@link Entity} with Id/name Set.
     * @return {@link CAEntity}/ {@link Entity} that is retrieved successfully.
     * @throws EntityCategoryNotFoundException
     *             Thrown when given entity category is not found in the system.
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given ID/Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             Thrown when the given entity Type is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             Thrown when Invalid Attribute is found while mapping Entity.
     * @throws InvalidEntityCategoryException
     *             Thrown when the given Entity category is invalid.
     */
    List<T> getEntitiesSummaryByCategory(EntityCategory entityCategory) throws EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException,
    InvalidEntityCategoryException;

    /**
     * This method is used for getting count of entities applying filter criteria, if any specified. It Does the following operation:
     * <ul>
     * <li>Retrieve all JPA Entity instances or JPA Entity instances based on filter if specified, .</li>
     * <li>Return the count of such instances.</li>
     * </ul>
     *
     * @param entitiesFilter
     *            specifies criteria based on which entities have to be filtered
     *
     * @return count of {@link CAEntity}/ {@link Entity} that are retrieved from DB.
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     */
    int getEntitiesCountByFilter(EntitiesFilter entitiesFilter) throws EntityServiceException;

    /**
     * This method fetches the list of {@link CAEntity}/{@link Entity} based on given status value
     *
     * @param entityStatus
     *            the integer value of status of {@link CAEntity}/{@link Entity}
     *
     * @return List of {@link CAEntity}/{@link Entity} which has given status value
     *
     *
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    List<T> getEntitiesByStatus(int status) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

}
