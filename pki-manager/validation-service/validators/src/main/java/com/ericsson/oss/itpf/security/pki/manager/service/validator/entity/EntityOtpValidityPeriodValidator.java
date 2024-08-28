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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.configuration.listener.PKIManagerConfigurationListener;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOtpValidityPeriodException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;

/**
 * This class is used to verify whether OTPValidityPeriod of a given entity {@link Entity} falls within the minimum and maximum values. Minimum value is 1. Maximum value is 1440.
 * 
 * The validation is skipped for the old entities where the value of OTPValidityPeriod is set as -1.
 * 
 *
 * @author zlaxsri
 */
public class EntityOtpValidityPeriodValidator implements CommonValidator<Entity> {

    @Inject
    PKIManagerConfigurationListener pkiManagerConfigurationListener;

    @Inject
    Logger logger;

    private final static int MIN_VALUE = 1;

    private final static int MAX_VALUE = 1440;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final Entity entity) throws ValidationException {
        validateOtpValidityPeriod(entity);
    }

    /**
     * This Method validates whether OTPValidityPeriod falls with in the minimum and maximum values of the entity i.e {@link Entity}
     * 
     * @param entity
     *            Object of Entity
     * @throws InvalidOtpValidityPeriodException
     *             thrown if the OTPValidityPeriod is not within the specified minimum and maximum values
     */
    private void validateOtpValidityPeriod(final Entity entity) throws InvalidOtpValidityPeriodException {
        logger.debug("Validating OTP Validity Period of Entity {}", entity.getOtpValidityPeriod());

        setOtpValidityPeriodWithConfiguredParam(entity);

        if (entity.getOtpValidityPeriod() != null && entity.getOtpValidityPeriod() != -1) {
            if (!((MIN_VALUE <= entity.getOtpValidityPeriod()) && (entity.getOtpValidityPeriod() <= MAX_VALUE))) {
                logger.error(ErrorMessages.OTP_VALIDITY_PERIOD_NOT_IN_RANGE, "{}", MIN_VALUE, "{} & ", MAX_VALUE);
                throw new InvalidOtpValidityPeriodException(ErrorMessages.OTP_VALIDITY_PERIOD_NOT_IN_RANGE + MIN_VALUE + " & " + MAX_VALUE);
            }
        }

        logger.debug("Completed validating Entity", entity.getOtpValidityPeriod());
    }

    /**
     * Sets the OTP Validity Period value to the Entity from default configured parameter if it is null
     * 
     * @param entity
     *            Object of CA Entity or Entity.
     */
    private <T extends AbstractEntity> void setOtpValidityPeriodWithConfiguredParam(final Entity entity) {
        Integer otpValidityPeriod = entity.getOtpValidityPeriod();
        if (otpValidityPeriod == null || otpValidityPeriod.equals(0)) {
            otpValidityPeriod = pkiManagerConfigurationListener.getDefaultOtpValidityPeriod();
            entity.setOtpValidityPeriod(otpValidityPeriod);
        }
    }

}
