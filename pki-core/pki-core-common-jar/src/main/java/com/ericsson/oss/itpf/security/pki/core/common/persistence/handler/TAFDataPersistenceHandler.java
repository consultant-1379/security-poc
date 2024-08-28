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
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;

/**
 * This class is responsible for clean up TAF data which is created during TAF
 * execution
 * 
 */
public class TAFDataPersistenceHandler {

	@Inject
	PersistenceManager persistenceManager;

	@Inject
	Logger logger;

	public List<String> getEntityNameListByPartOfName(final String queryStr,
			final String partOfEntityName) {
		List<String> entitiesNames = new ArrayList<>();
		try {

			final Query query = persistenceManager.getEntityManager()
					.createNativeQuery(queryStr);
			query.setParameter("name_part", partOfEntityName + "%");

			entitiesNames = query.getResultList();

		} catch (final PersistenceException persistenceException) {
			logger.error(
					"Error occured while getting core entities from database",
					persistenceException.getMessage(), persistenceException);
		}

		return entitiesNames;
	}

	public Long getDataEntityId(final String queryStr,
			final Map<String, Object> attributes) {

		Long entityId = 0L;
		try {
			final Query query = persistenceManager.getEntityManager()
					.createNativeQuery(queryStr);
			for (Map.Entry<String,Object> entry : attributes.entrySet()) {
				final String key = entry.getKey();
				final Object value = entry.getValue();
				query.setParameter(key, value);
			}

			entityId = Long.valueOf(String.valueOf(query.getSingleResult()));

		} catch (final Exception e) {
			logger.error(queryStr + " :: values :: " + attributes.values());
			logger.error(
					"Error occured while reading TAF core data from database",
					e.getMessage(), e);
		}

		return entityId;
	}

	public List<Long> getDataEntityIdList(final String queryStr,
			final Map<String, Object> attributes) {

		final List<Long> entityIdList = new ArrayList<>();

		try {

			final Query query = persistenceManager.getEntityManager()
					.createNativeQuery(queryStr);
			for (Map.Entry<String,Object> entry : attributes.entrySet()) {
				final String key = entry.getKey();
				final Object value = entry.getValue();
				query.setParameter(key,value);
			}

			final List<Object[]> objects = query.getResultList();

			for (final Object eachObject : objects) {
				if (eachObject != null) {
					entityIdList.add(Long.valueOf(String.valueOf(eachObject)));
				}
			}

		} catch (final Exception e) {
			logger.error(queryStr + " :: values :: " + attributes.values());
			logger.error(
					"Error occured while reading list TAF core data from database",
					e.getMessage(), e);
		}

		return entityIdList;
	}

	public void deleteTAFEntity(final String queryStr,
			final Map<String, Object> attributes) {

		try {

			final Query query = persistenceManager.getEntityManager()
					.createNativeQuery(queryStr);
			for (Map.Entry<String, Object> entry : attributes.entrySet()) {
				final String key = entry.getKey();
				final Object value = entry.getValue();
				query.setParameter(key, value);
			}
			persistenceManager.getEntityManager().joinTransaction();
			query.executeUpdate();

		} catch (final PersistenceException persistenceException) {
			logger.error(queryStr + " :: values :: " + attributes.values());
			logger.error(
					"Error occured while deleting TAF core entities from database",
					persistenceException.getMessage(), persistenceException);
		}
	}

}
