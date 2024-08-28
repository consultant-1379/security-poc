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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntityDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;

/**
 * This interface is provided for handling the calls related to entity management
 * 
 * @author tcspred
 * 
 */
@EService
@Local
public interface EntityManagementServiceLocal {

    /**
     * Returns count of Entities that match with the given filter criteria.
     * 
     * @param entitiesFilter
     *            specifies criteria based on which entities have to be filtered
     * @return count of entities matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    int getEntitiesCountByFilter(EntitiesFilter entitiesFilter) throws EntityServiceException;

    /**
     * Returns list of Entities that match with the given filter criteria and that lie between given offset, limit values.
     * 
     * @param entitiesFilter
     *            specifies criteria, offset, limit values based on which entities have to be filtered
     * @return list of entities between given offset, limit values matching given criteria
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    List<AbstractEntityDetails> getEntityDetailsByFilter(EntitiesFilter entitiesFilter) throws EntityServiceException;

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
    List<CAEntity> fetchCAEntitiesIdAndName(CAStatus caStatus, boolean externalCARequired) throws EntityServiceException, InvalidEntityException;
}
