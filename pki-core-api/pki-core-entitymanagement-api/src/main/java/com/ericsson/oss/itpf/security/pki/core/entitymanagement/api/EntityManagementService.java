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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

/**
 * This is an interface for entity management service and provides API's for below operations.
 * <ul>
 * <li>Creation of entities</li>
 * <li>Update of entities</li>
 * <li>Deletion of entities</li>
 * </ul>
 *
 * @author xrajaba
 * @since 21/07/15
 */

@EService
@Remote
public interface EntityManagementService {

    /**
     * Creates {@link EntityInfo}.
     *
     * @param entityInfo
     *            entityInfo object to be created.
     * @return created entityInfo object
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case when creating {@link EntityInfo} object that already exists.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the EndEntity.
     */
    EntityInfo createEntity(EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException;

    /**
     * Updates {@link EntityInfo} object.
     *
     * @param entityInfo
     *            entityInfo object to be updated in database.
     * @return updated entityInfo Object
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case when updating with name that already exists.
     * @throws CoreEntityNotFoundException
     *             Thrown in case when updating {@link EntityInfo} object that does not exist.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the EndEntity.
     */
    EntityInfo updateEntity(EntityInfo entityInfo) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException, InvalidCoreEntityAttributeException;

    /**
     * Deletes {@link EntityInfo} object.
     *
     * @param entityInfo
     *            entityInfo object to be deleted.
     * @throws CoreEntityInUseException
     *             Thrown in case when {@link EntityInfo} has active certificate.
     * @throws CoreEntityNotFoundException
     *             Thrown in case when deleting {@link EntityInfo} object that does not exist.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     *
     */
    void deleteEntity(EntityInfo entityInfo) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException ;

    /**
     * This method is used to update OTP and OTP Count for an Entity.
     *
     * @param entityName
     *            Name of the entity for which otp to be validated.
     * @param otp
     *            updated OTP value
     * @param otpCount
     *            updated OTP Count
     * @throws CoreEntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     */
    void updateOTP(String entityName, String otp, int otpCount) throws CoreEntityNotFoundException, CoreEntityServiceException;

    /**
     * This method is used to import EntityInfo
     *
     * @param entityInfoList
     *            List EntityInfo object to be created.
     * @return EntityInfoList List of EntityInfo objects created.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown when creating {@#link CertificateAuthority} object that already exists.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     *
     */
    List<EntityInfo> importEntities(List<EntityInfo> entityInfoList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException;

    /**
     * This method will update Entity status to INACTIVE for all the Entities who does not have active or inactive certificates.
     *
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */
    void updateEntityStatusToInactive() throws CoreEntityServiceException;
}
