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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb.custom;

import java.util.Date;
import java.util.List;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.custom.EntityManagementCustomService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;

/**
 * This class implements {@link ProfileManagementService}
 *
 */
@Profiled
@Stateless
public class EntityManagementCustomServiceBean implements EntityManagementCustomService {

    @Inject
    private Logger logger;

    @Inject
    private EntitiesManager entitiesManager;

    @Override
    public List<Entity> getEntitiesWithInvalidCertificate(final Date notAfter, final int maxEntities, final EntityCategory... entityCategories) throws EntityCategoryNotFoundException,
            EntityServiceException, MissingMandatoryFieldException,InvalidEntityAttributeException, InvalidEntityException {
        logger.info("Get entities by category with invalid certificate");
        return entitiesManager.getEntitiesWithInvalidCertificate(notAfter, maxEntities, entityCategories);
    }

}
