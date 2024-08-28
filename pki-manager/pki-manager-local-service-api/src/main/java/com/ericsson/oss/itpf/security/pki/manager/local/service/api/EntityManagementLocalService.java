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
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPNotSetException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This class provides interfaces to getOTP and to check OTP is valid or not .
 * 
 * @author tcsramc
 *
 */
@EService
@Local
public interface EntityManagementLocalService {

    /**
     * This method is used to get OTP value for the given entity.
     * 
     * @param entityName
     *            entity for which OTP value has to be fetched
     * @return OTP value
     * @throws OTPNotSetException
     *             is thrown if OTP value is null
     * @throws OTPExpiredException
     *             is thrown if OTP value is zero
     * @throws EntityNotFoundException
     *             is thrown if entity is not found in the database.
     * @throws EntityServiceException
     *             is thrown if any exception occurred while fetching entity info from the database
     */
    String getOTP(final String entityName) throws OTPNotSetException, OTPExpiredException, EntityNotFoundException, EntityServiceException;

    /**
     * This method is used in case of SCEP for validating OTP
     * 
     * @param entityName
     *            Name of the entity for which otp to be validated.
     * @param otp
     * 
     * @return true/false
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0 to inform CREDM that the existing OTP is no longer valid
     */
    boolean isOTPValid(String entityName, String otp) throws EntityNotFoundException, EntityServiceException, OTPExpiredException;

    /**
     * This method is get entity based on entity subject DN and issuer DN
     * 
     * @param entitySubjectDN
     *            The entity subject DN
     * @param issuerDN
     *            The issuer of the entity
     * @return Entity
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidEntityAttributeException
     *             Thrown when subject DN is in improper format.
     */
    Entity getEntity(final String entitySubjectDN, final String issuerDN) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException;

    /**
     * This method is used to remove the inconsistencies between hash of subject_dn column of entity table and subject_dn_hash of subject_identification_details table.
     */
    void syncMismatchEntities();

    /**
     * Delete an entity in pki manager
     * 
     * @param entityName
     *            name of the entity which should be deleted
     * @throws EntityAlreadyDeletedException
     *             thrown when given entity is already deleted.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any other profile.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    <T extends AbstractEntity> void deletePkiManagerEntity(final String entityName)
            throws EntityAlreadyDeletedException, EntityNotFoundException, EntityInUseException, EntityServiceException, InvalidEntityAttributeException;

}
