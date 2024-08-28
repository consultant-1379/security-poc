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
package com.ericsson.oss.itpf.security.pki.common.persistence;

import java.util.List;
import java.util.StringTokenizer;

import javax.inject.Inject;
import javax.persistence.*;
import javax.persistence.criteria.*;

import org.slf4j.Logger;

/**
 * Class which does all DB related operations.
 */
public abstract class AbstractPersistenceManager {

    @Inject
    Logger logger;

    private static final String PATH_DELIMITER = ".";

    /**
     * @return the entityManager
     */
    public abstract EntityManager getEntityManager();

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
        getEntityManager().persist(entity);
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
        final T mergedEntity = getEntityManager().merge(entity);
        return mergedEntity;
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
    public <T> T findEntity(final Class<T> entityClass, final String id) throws PersistenceException {
        logger.debug("Finding entity {} by ID {}", entityClass, id);

        final T entityResponse = getEntityManager().find(entityClass, id);
        return entityResponse;
    }

    /**
     * The method which executes a native query and returns the result set.
     *
     * @param executableQuery
     *            query to be executed.
     * @return result set.
     */
    public <T> List<T> createNativeQuery(final String executableQuery) {
        final Query query = getEntityManager().createNativeQuery(executableQuery);

        return query.getResultList();
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
    public <T> T findEntityByKeyIdentifier(final Class<T> entityClass, final String name, final String namePath) throws PersistenceException {
        logger.debug("Finding entity {} by name {}", entityClass, name);

        final CriteriaBuilder criteriaBuilder = getEntityManager().getCriteriaBuilder();

        final CriteriaQuery<T> criteriaQuery = criteriaBuilder.createQuery(entityClass);

        final Root<T> entity = criteriaQuery.from(entityClass);
        final Path<T> path = getPathFromString(namePath, entity);
        final Expression<String> nameExpression = (Expression<String>) path;
        criteriaQuery.where(criteriaBuilder.equal(criteriaBuilder.lower(nameExpression), name.toLowerCase()));

        final TypedQuery<T> query = getEntityManager().createQuery(criteriaQuery);

        T Object = null;
        final List<T> Objects = query.getResultList();
        if (Objects.size() != 0) {
            Object = Objects.get(0);
        }
        return Object;
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
     * @param className
     * @return
     */
    public <T> List<T> findEntityByQuery(final Class<?> className) {

        final String executableQuery = getQuery(className);

        final Query query = getEntityManager().createQuery(executableQuery);

        return query.getResultList();
    }

    private String getQuery(final Class<?> className) {
        return "SELECT entity FROM " + className.getSimpleName() + " entity ";
    }

}
