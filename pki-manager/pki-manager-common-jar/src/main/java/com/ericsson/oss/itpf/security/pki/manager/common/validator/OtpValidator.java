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
package com.ericsson.oss.itpf.security.pki.manager.common.validator;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;

/**
 * OtpValidator validates a OTP/challenge password for a given entity during certificate generation. The class will return exceptions EntityNotFoundException and OTPExpiredException.
 * EntityNotFoundException will be returned when the entity name is not present for the certificate generation. The OTPExpiredException will be return when the OTP count will reachs the maximum
 * attempts during the certificate generation for the entity
 * 
 * @author xananer
 * 
 */

public class OtpValidator {

    @Inject
    private Logger logger;

    @Inject
    private PersistenceManager persistenceManager;

    /**
     * The method validates the otp for a given entity name during certificate generation . If the entity is not found the EntityNotFoundException will be thrown and when the otp count reaches 0 then
     * OTPExpiredException will be thrown during the validation.
     * 
     * @param entityName
     *            is the name of the entity for which the certificate has to be generated.
     * @param otp
     *            is the Challenge password used for the validation of a entity.
     * @return true if the validation of the OTP is successful for the given entity/OTP combination. false if the validation of the OTP is failed for the given entity/OTP combination.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0.
     * @throws EntityServiceException
     *             Thrown when there are any DB Errors retrieving the Entity Data.
     */

    public boolean isOtpValid(final String entityName, final String otp) throws EntityNotFoundException, OTPExpiredException, EntityServiceException {

        logger.info("Entering method extractCsrAttributes of class ScepRequestProcessor ");

        try {
            final EntityData entityData = persistenceManager.findEntityByName(EntityData.class, entityName, "entityInfoData.name");

            if (entityData == null) {
                throw new EntityNotFoundException("Entity Not found Exception");
            }
            if (entityData.getEntityInfoData().getOtpCount() <= 0) {
                throw new OTPExpiredException("OTP Expired");
            }

            if (entityData.getEntityInfoData().getOtp() == null || entityData.getEntityInfoData().getOtp().equals("")) {
                if (otp == null || otp.equals("")) {
                    logger.info("Entity with empty OTP found", entityName);
                    return true;
                } else {
                    logger.error("OTP is not found for the entity{} in the database.OTP validation failed", entityName);
                    return false;
                }
            }

            int count = entityData.getEntityInfoData().getOtpCount();
            count--;
            entityData.getEntityInfoData().setOtpCount(count);
            persistenceManager.updateEntity(entityData);
            if (otp != null && !otp.equals("")) {
                if (entityData.getEntityInfoData().getOtp().equals(otp)) {
                    logger.info("End of method extractCsrAttributes of class ScepRequestProcessor ");
                    return true;
                }
            }
        } catch (final PersistenceException e) {
            throw new EntityServiceException("Failed to extract entity ", e);
        }
        logger.info("End of method extractCsrAttributes of class ScepRequestProcessor ");
        return false;
    }

}
