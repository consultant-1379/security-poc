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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import java.util.Date;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPNotSetException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;

/**
 * This class is used to check whether the OTP given in entity is expired or not.
 * 
 * OTP expiry is validated using the expression (currentTime-otpGeneratedTime > otpValidityPeriod) and will throw OTPExpiredException, if it is expired.
 * 
 * The validation is skipped for the old entities where the value of OTPValidityPeriod is set as -1.
 * 
 * @author tcsramc
 *
 */
public class EntityOtpExpirationValidator implements CommonValidator<Entity> {

    @Inject
    protected EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Inject
    Logger logger;

    private final static String NAME_PATH = "entityInfoData.name";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {
        validateOtpExpiration(entity);
    }

    /**
     * The method validates OTP using the expression (currentTime-otpGeneratedTime > otpValidityPeriod) and will throw OTPExpiredException, if it is expired.
     * 
     * @param entity
     *            Object of Entity
     * @throws EntityNotFoundException
     *             Thrown when no entity found with given Name.
     * @throws EntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws OTPExpiredException
     *             Thrown when OTP is expired
     * @throws OTPNotSetException
     *             Thrown incase OTP is not set for the entity.
     */
    private void validateOtpExpiration(final Entity entity) throws EntityNotFoundException, EntityServiceException, OTPExpiredException, OTPNotSetException {
        EntityData entityData = null;

        entityData = getEntitiesPersistenceHandler().getEntityByName(entity.getEntityInfo().getName(), EntityData.class, NAME_PATH);
        validateOtpCount(entityData);
        if (entityData.getOtpValidityPeriod() != null && entityData.getOtpValidityPeriod() != -1) {

            if (((new Date().getTime()) - entityData.getOtpGeneratedTime().getTime()) > (entityData.getOtpValidityPeriod()) * 60 * 1000) {
                entityData.getEntityInfoData().setOtpCount(0);
                logger.error(ErrorMessages.OTP_EXPIRED, "{}", entityData.getEntityInfoData().getName());
                throw new OTPExpiredException(ErrorMessages.OTP_EXPIRED);
            }
        }
    }

    /**
     * This method is used to check otp count validity of a given entity.
     * 
     * @param entityData
     *            from which otp has to extract and validate
     * @throws OTPExpiredException
     *             Thrown if otp is expired
     * @throws OTPNotSetException
     *             Thrown if otp is null
     */
    private void validateOtpCount(final EntityData entityData) throws OTPExpiredException, OTPNotSetException {
        final int oTPCount = entityData.getEntityInfoData().getOtpCount();

        if (entityData.getEntityInfoData().getOtp() == null) {
            throw new OTPNotSetException(ErrorMessages.OTP_NOT_SET);
        }
        if (oTPCount <= 0) {
            throw new OTPExpiredException(ErrorMessages.OTP_EXPIRED);
        }
    }

    /**
     * This method calls the {@link EntitiesPersistenceHandlerFactory} to get the appropriate {@link EntitiesPersistenceHandler} instance ( {@link EntityPersistenceHandler} ).
     *
     * @return instance of {@link EntitiesPersistenceHandler} ( {@link EntityPersistenceHandler} ).
     *
     */
    private EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler() {
        return entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY);
    }
}
