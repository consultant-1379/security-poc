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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.service;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl.EntityManager;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

@Profiled
@Stateless
public class EntityManagementServiceBean implements EntityManagementService {

    @Inject
    EntityManager entitiesManager;

    @Inject
    Logger logger;

    @EJB
    BulkImportLocalServiceBean bulkImportLocalServiceBean;

    @Override
    public EntityInfo createEntity(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException {

        final EntityInfo enInfo = entitiesManager.createEntity(entityInfo);

        logger.debug("Created {}", entityInfo.getName());
        return enInfo;
    }

    @Override
    public EntityInfo updateEntity(final EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException, InvalidCoreEntityAttributeException {

        final EntityInfo enInfo = entitiesManager.updateEntity(entityInfo);

        logger.debug("Updated {}", entityInfo.getName());
        return enInfo;
    }

    @Override
    public void deleteEntity(final EntityInfo entityInfo) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException {

        entitiesManager.deleteEntity(entityInfo);

        logger.debug("Deleted {}", entityInfo.getName());
    }

    @Override
    public void updateOTP(final String entityName, final String otp, final int otpCount) throws CoreEntityNotFoundException, CoreEntityServiceException {
        // TODO Auto-generated method stub
    }

    /**
     * Method used to validate and create EntityInfo in Bulk
     * 
     * @param entityInfoList
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public List<EntityInfo> importEntities(final List<EntityInfo> entityInfoList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        bulkImportLocalServiceBean.importEntityInfo(entityInfoList);
        return entityInfoList;
    }

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     * 
     * @throws CoreEntityServiceException
     */

    public void updateEntityStatusToInactive() throws CoreEntityServiceException {
        entitiesManager.updateEntityStatusToInactive();
    }

}
