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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.rest.EntityManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntityDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.EntityManagementServiceLocal;

/**
 * This class implements {@link EntityManagementServiceLocal} for handling the calls related to entity management
 * 
 * @author tcspred
 * 
 */
@Profiled
@Stateless
public class EntityManagementServiceLocalBean implements EntityManagementServiceLocal {

    @Inject
    private EntitiesManager entitiesManager;

    @Inject
    private Logger logger;

    @Inject
    private EntityManagementAuthorizationHandler entityManagementAuthorizationHandler;

    /**
     * This method returns count of {@link CAEntity}/{@link Entity} that match with the given filter criteria
     * 
     * @param entitiesFilter
     *            EntitiesFilter object specifying criteria based on which entities have to be filtered
     * @return integer count of entities matching given criteria
     * @throws EntityServiceException
     */
    @Override
    public int getEntitiesCountByFilter(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        authorizeReadOperations(entitiesFilter);
        logger.debug("get count of Entities that match the given filter dto {} ", entitiesFilter);

        final int count = entitiesManager.getEntitiesCountByFilter(entitiesFilter);

        logger.debug("Retrieved count of Entities that match with the given filter criteria");

        return count;
    }

    /**
     * This method returns list of {@link CAEntity / @link Entity} that match with the given filter criteria and that lie between given offset, limit values.
     * 
     * @param entitiesFilter
     *            EntitiesFilter object specifying criteria, offset, limit values based on which entities have to be filtered
     * @return list of entities between given offset, limit values matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public List<AbstractEntityDetails> getEntityDetailsByFilter(final EntitiesFilter entitiesFilter) throws EntityServiceException {
        authorizeReadOperations(entitiesFilter);
        logger.debug("getEntityDetailsByFilter by filter {} ", entitiesFilter);

        final List<AbstractEntityDetails> entitiesList = entitiesManager.getEntityDetailsByFilter(entitiesFilter);

        logger.debug("Retrieved Entities between given offset, limit values that match with given filter criteria");

        return entitiesList;
    }

    /**
     * This method authorizes the operations to be performed according to the user's role.
     * 
     * @param entitiesFilter
     */
    private void authorizeReadOperations(final EntitiesFilter entitiesFilter) {
        if (ValidationUtils.isNullOrEmpty(entitiesFilter.getType())) {
            //adding default values in case of default filter
            final List<EntityType> entityTypes = new ArrayList<EntityType>();
            entityTypes.add(EntityType.CA_ENTITY);
            entityTypes.add(EntityType.ENTITY);
            entitiesFilter.setType(entityTypes);
        }
        final Iterator<EntityType> iterator = entitiesFilter.getType().iterator();
        while (iterator.hasNext()) {
            try {
                switch (iterator.next()) {
                case CA_ENTITY: {
                    entityManagementAuthorizationHandler.authorizeListCAEntities();
                    break;
                }
                case ENTITY: {
                    entityManagementAuthorizationHandler.authorizeListEntities();
                    break;
                }
                }
            } catch (final SecurityViolationException e) {
                logger.debug("Security Violation occured ", e);
                iterator.remove();
            }
        }
        if (ValidationUtils.isNullOrEmpty(entitiesFilter.getType())) {
            logger.error("User is Not authorized to perform operation");
            throw new SecurityViolationException("access control decision: denied to invoke: read on resource: reading entities");
        }
    }

    /**
     * Returns id and name of CA Entities based on status provided and externalCARequired flag.
     * 
     * @param caStatus
     *            status of CA Entity.
     * @param externalCARequired
     *            boolean externalCA.
     * @return list of id and name of CA Entities with status
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity type is other than caentity/entity.
     */
    @Override
    public List<CAEntity> fetchCAEntitiesIdAndName(final CAStatus caStatus, final boolean externalCARequired) throws EntityServiceException, InvalidEntityException {

        entityManagementAuthorizationHandler.authorizeListCAEntities();

        logger.debug("fetch CA entities id and name");

        final List<CAEntity> issuersList = entitiesManager.fetchCAEntitiesIdAndName(caStatus, externalCARequired);

        logger.debug("Retrieved list of active CA entities");

        return issuersList;
    }
}
