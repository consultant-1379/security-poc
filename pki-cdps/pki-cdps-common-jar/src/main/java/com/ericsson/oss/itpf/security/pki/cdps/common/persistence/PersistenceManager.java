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
package com.ericsson.oss.itpf.security.pki.cdps.common.persistence;

import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;
import javax.persistence.criteria.*;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.persistence.AbstractPersistenceManager;

/**
 * This class provides generic methods to do DB Operation and execute queries.
 * 
 * @author xjagcho
 */
public class PersistenceManager extends AbstractPersistenceManager {

    @PersistenceContext(unitName = "PKICDPS")
    private EntityManager entityManager;

    @Inject
    private Logger logger;

    private static final String PATH_DELIMITER = ".";

    /**
     * Returns entity manager.
     * 
     * @return the entityManager
     */
    public EntityManager getEntityManager() {
        return entityManager;
    }

    /**
     * The method for finding the entity using IN Condition with multiple attributes.
     * 
     * @param entityClass
     *            Class of JPA Entity on which this operation to be done.
     * @param input
     *            {@link java.util.Map} containing attribute and its value that are to be used in WHERE condition in query.
     * @return list of JPA Entities fetched from DB.
     * @throws PersistenceException
     *             Parent Exception in JPA. Thrown when there are any DB Errors while persisting.
     */
    public <T> List<T> findEntitiesWhere(final Class<T> entityClass, final Map<String, Object> input) throws PersistenceException {
        logger.debug("Finding entity {} by inputParams {}", entityClass, input);

        final CriteriaBuilder criteriaBuilder = entityManager.getCriteriaBuilder();
        final CriteriaQuery<T> criteriaQuery = criteriaBuilder.createQuery(entityClass);

        final Root<T> entity = criteriaQuery.from(entityClass);
        final List<Predicate> predicatesList = new ArrayList<Predicate>();

        for (final String key : input.keySet()) {
            Expression<String> fieldExpression = entity.get(key);
            Predicate predicate = null;

            if (isKeyContainsPath(key)) {
                fieldExpression = getExpressionFromString(key, entity);
            }

            if (input.get(key) instanceof String) {
                predicate = criteriaBuilder.equal(criteriaBuilder.lower(fieldExpression), input.get(key).toString().toLowerCase());
            } else if (input.get(key) instanceof Collection<?>) {
                final Collection<?> inputParams = (Collection<?>) input.get(key);
                final Class<?> typeClass = fieldExpression.getJavaType();

                if (typeClass.equals(Set.class) || typeClass.equals(List.class)) {
                    predicate = entity.join(key).in(inputParams);
                } else {
                    predicate = entity.get(key).in(inputParams);
                }
            } else {
                predicate = criteriaBuilder.equal(fieldExpression, input.get(key));
            }
            predicatesList.add(predicate);
        }

        if (predicatesList.size() > 1) {
            criteriaQuery.where(criteriaBuilder.and(predicatesList.toArray(new Predicate[predicatesList.size()])));
        } else {
            criteriaQuery.where(predicatesList.toArray(new Predicate[predicatesList.size()]));
        }
        final TypedQuery<T> query = entityManager.createQuery(criteriaQuery);

        final List<T> Objects = query.getResultList();

        return Objects;
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
        logger.debug("Deleting Entity", entity.getClass().getSimpleName());
        entityManager.remove(entity);
        entityManager.flush();
    }

    private boolean isKeyContainsPath(final String key) {
        return key.contains(PATH_DELIMITER);
    }

    private <T> Expression<String> getExpressionFromString(final String fieldPath, final Root<T> entity) {
        final StringTokenizer stringTokenizer = new StringTokenizer(fieldPath, PATH_DELIMITER);
        Path<T> path = entity.get(stringTokenizer.nextElement().toString());
        Expression<String> expression = null;
        while (stringTokenizer.hasMoreElements()) {
            final String element = stringTokenizer.nextElement().toString();
            if (stringTokenizer.hasMoreElements()) {
                path = path.get(element);
            } else {
                expression = path.get(element);
            }
        }
        return expression;
    }
}
