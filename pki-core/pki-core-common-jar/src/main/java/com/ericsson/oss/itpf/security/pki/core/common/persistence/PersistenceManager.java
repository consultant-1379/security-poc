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
package com.ericsson.oss.itpf.security.pki.core.common.persistence;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;
import javax.persistence.criteria.*;

import org.slf4j.Logger;

public class PersistenceManager {

    @PersistenceContext(unitName = "PKICore")
    private EntityManager entityManager;

    @Inject
    Logger logger;

    private static final String PATH_DELIMITER = ".";

    private static final String ID = "id";

    /**
     * @return the entityManager
     */
    public EntityManager getEntityManager() {
        return entityManager;
    }

    /**
     * The method for creating an entity in database
     * 
     * @param entity
     *            Object of any JPA Entity that can be persistable.
     * @throws EntityExistsException
     *             Thrown incase entity already exists in database.
     * @throws TransactionRequiredException
     *             Thrown in case transaction is needed for this operation.
     */
    public <T> void createEntity(final T entity) throws EntityExistsException, TransactionRequiredException {

        logger.debug("Persisting entity {}", entity.getClass().getSimpleName());
        entityManager.persist(entity);
        entityManager.flush();
    }

    /**
     * Updates the entity in the database.
     * 
     * @param entity
     *            entity to be updated in the database.
     * @return updated entity from the database.
     * @throws TransactionRequiredException
     *             Thrown in case transaction is needed for this operation.
     */
    public <T> T updateEntity(final T entity) throws TransactionRequiredException {

        logger.debug("Updating entity {}", entity.getClass().getSimpleName());
        final T mergedEntity = entityManager.merge(entity);
        entityManager.flush();
        return mergedEntity;
    }

    /**
     * Refresh the state of the instance from the database, overwriting changes made to the entity, if any.
     * 
     * @param entity
     *            entity to be updated in the database.
     * @throws EntityNotFoundException
     *             Thrown in case entity not found in the database.
     * @throws TransactionRequiredException
     *             Thrown in case transaction is needed for this operation.
     */
    public <T> void refresh(final T entity) throws EntityNotFoundException, TransactionRequiredException {

        logger.debug("Refreshing entity {}", entity.getClass().getSimpleName());
        entityManager.refresh(entity);
    }

    /**
     * Find entities by attributes
     * 
     * @param entityClass
     *            Class of the entity to be retrieved.
     * @param attributes
     *            Attributes map containing entity property names and values.
     * @return list of entities which matches the attributes.
     * @throws PersistenceException
     *             Parent Exception in JPA. Thrown when there are any DB Errors while persisting.
     */
    public <T> List<T> findEntitiesByAttributes(final Class<T> entityClass, final Map<String, Object> attributes) throws PersistenceException {
        List<T> results = null;
        final CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        final CriteriaQuery<T> cq = cb.createQuery(entityClass);
        final Root<T> entity = cq.from(entityClass);

        final List<Predicate> predicates = new ArrayList<>();
        for (Map.Entry<String,Object> entry : attributes.entrySet()) {
            final String key = entry.getKey();
            final Object object = entry.getValue();
            if (entity.get(key)!= null && object != null) {
                if (object instanceof String || object instanceof Boolean || object instanceof Integer || object instanceof Long) {
                    predicates.add(cb.equal(entity.get(entry.getKey()), object));
                } else if (object instanceof List) {
                    predicates.add(entity.get(key).in(object));
                }
            }
        }
        cq.where(predicates.toArray(new Predicate[] {}));
        final TypedQuery<T> q = entityManager.createQuery(cq);
        results = q.getResultList();
        return results;
    }

    /**
     * The method for finding the entity using name
     * 
     * @param entityClass
     *            Class of JPA Entity on which this operation to be done.
     * @param name
     *            Unique Name using which entity need to be fetched.
     * @param namePath
     *            Path of the 'name' attribute in JPAEntity.
     * @return JPA Entity fetched from DB.
     * @throws PersistenceException
     *             Parent Exception in JPA. Thrown when there are any DB Errors while persisting.
     */
    public <T> T findEntityByName(final Class<T> entityClass, final String name, final String namePath) throws PersistenceException {
        logger.debug("Finding entity {} by name {}", entityClass, name);

        final CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();

        final CriteriaQuery<T> criteriaQuery = criteriaBuilder.createQuery(entityClass);

        final Root<T> entity = criteriaQuery.from(entityClass);
        final Path<T> path = getPathFromString(namePath, entity);
        final Expression<String> nameExpression = (Expression<String>) path;
        criteriaQuery.where(criteriaBuilder.equal(criteriaBuilder.lower(nameExpression), name.toLowerCase()));

        final TypedQuery<T> query = entityManager.createQuery(criteriaQuery);

        T object = null;
        final List<T> objects = query.getResultList();
        if (!objects.isEmpty()) {
            object = objects.get(0);
        }
        return object;
    }

    /**
     * The method for finding an entity in database
     * 
     * @param entityClass
     *            Class of JPA Entity on which this operation to be done.
     * @param id
     *            Unique Id using which entity need to be fetched.
     * @return JPA Entity fetched from DB.
     * @throws PersistenceException
     *             Parent Exception in JPA. Thrown when there are any DB Errors while persisting.
     */
    public <T> T findEntity(final Class<T> entityClass, final long id) throws PersistenceException {
        logger.debug("Finding entity {} by ID {}", entityClass, id);

        return entityManager.find(entityClass, id);
    }

    /**
     * The method for finding the entity based on id and name
     * 
     * @param entityClass
     *            Class of JPA Entity on which this operation to be done.
     * @param id
     *            Unique Id using which entity need to be fetched.
     * @param name
     *            Unique Name using which entity need to be fetched.
     * @param namePath
     *            Path of the 'name' attribute in JPAEntity.
     * @return JPA Entity fetched from DB.
     * @throws PersistenceException
     *             Parent Exception in JPA. Thrown when there are any DB Errors while persisting.
     */
    public <T> T findEntityByIdAndName(final Class<T> entityClass, final long id, final String name, final String namePath) throws PersistenceException {
        logger.debug("Finding entity {} by name {}", entityClass, name);

        final CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();

        final CriteriaQuery<T> criteriaQuery = criteriaBuilder.createQuery(entityClass);

        final Root<T> entity = criteriaQuery.from(entityClass);
        final Path<T> path = getPathFromString(namePath, entity);
        final Expression<String> nameExpression = (Expression<String>) path;
        criteriaQuery.where(criteriaBuilder.and(criteriaBuilder.equal(entity.get(ID), id), criteriaBuilder.equal(criteriaBuilder.lower(nameExpression), name.toLowerCase())));

        final TypedQuery<T> query = entityManager.createQuery(criteriaQuery);

        T object = null;
        final List<T> objects = query.getResultList();
        if (!objects.isEmpty()) {
            object = objects.get(0);
        }
        return object;
    }

    private <T> Path<T> getPathFromString(final String fieldPath, final Root<T> entity) {
        final StringTokenizer stringTokenizer = new StringTokenizer(fieldPath, PATH_DELIMITER);
        Path<T> path = entity.get(stringTokenizer.nextElement().toString());
        while (stringTokenizer.hasMoreElements()) {
            path = path.get(stringTokenizer.nextElement().toString());
        }
        return path;
    }

    /**
     * The method for deleting an entity
     * 
     * @param entity
     *            JPA Entity record that is to be deleted from DB.
     * @throws PersistenceException
     *             Parent Exception in JPA. Thrown when there are any DB Errors while persisting.
     */
    public <T> void deleteEntity(final T entity) throws PersistenceException {
        logger.debug("Deleting Entity: {}", entity.getClass().getSimpleName());
        entityManager.remove(entity);
        entityManager.flush();
    }

    /**
     * The method for updating the certificate status
     * 
     * @param certificateID
     *            id of the certificate
     * @param certificateStatus
     *            status of the certificate
     */
    public <T> void updateCertificateStatus(final long certificateID, final int certificateStatus) {
        final Query query = entityManager.createQuery("update CertificateData set status = :status_id where id = :id");
        query.setParameter("status_id", certificateStatus);
        query.setParameter("id", certificateID);
        query.executeUpdate();
    }

}
