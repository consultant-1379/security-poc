/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.custom;

import java.util.Date;
import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This is an interface for entity management service and provides API's for below operations.
 * <ul>
 * <li>Get entities with invalid cerficate.</li>
 * <li></li>
 * </ul>
 */
@EService
@Remote
public interface EntityManagementCustomService {

    /**
     * Get a list of entities filtered by category and without active certificate or certificate expired at the given date.
     *
     * @param notAfter
     *            The date to check the certificate validity
     * @param maxEntities
     *            The maximum number of Entities retrieved. Set to a negative value to retrieve all the filtered Entities.
     * @param entityCategory
     *            EntityCategory list
     * @return Returns list of entities based on the value sent in EntityCategory object at the notAfter date.
     *
     * @throws MissingMandatoryFieldException
     *             thrown if the notAfter date is null.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     *
     */
    List<Entity> getEntitiesWithInvalidCertificate(Date notAfter, int maxEntities, EntityCategory... entityCategories) throws EntityCategoryNotFoundException, EntityServiceException,
            MissingMandatoryFieldException;

}
