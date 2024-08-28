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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.entity;

import java.util.LinkedList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entity.EntityOtpExpirationValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entity.EntityOtpValidityPeriodValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.BaseValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/**
 * This class is used to get the respective validators to validate an Otp of an entity. ItemType is : ENTITY_OTP(entityotp), for this validation service.
 * 
 * @author tcsramc
 *
 */
@ServiceQualifier(ItemType.ENTITY_OTP)
public class OTPValidationService extends BaseValidationService<Entity> {

    @Inject
    EntityOtpValidityPeriodValidator entityOtpValidityPeriodValidator;

    @Inject
    EntityOtpExpirationValidator entityOtpExpirationValidator;

    /**
     * This method is used to fetch respective validators based on the parameters set in validateItem object. If skipOptionalTests is true, OTP Expiration validation is skipped. If it is false, OTP
     * Validity period validation is skipped.
     */
    @Override
    public List<CommonValidator<Entity>> getValidators(final ValidateItem validateItem) {
        final List<CommonValidator<Entity>> otpValidators = new LinkedList<CommonValidator<Entity>>();
        otpValidators.add(getEntityOtpValidator(validateItem.getOperationType()));
        return otpValidators;
    }

    /**
     * This method returns the respective entity otp validator class for given operationType i.e. either create, update or validate
     * 
     * @param operationType
     * @return CommonValidator<Entity>
     */
    private CommonValidator<Entity> getEntityOtpValidator(final OperationType operationType) {
        CommonValidator<Entity> validator = null;
        switch (operationType) {
        case CREATE:
            validator = entityOtpValidityPeriodValidator;
            break;
        case UPDATE:
            validator = entityOtpValidityPeriodValidator;
            break;
        case VALIDATE:
            validator = entityOtpExpirationValidator;
            break;
        default:
            throw new IllegalArgumentException("Invalid Operation Type");
        }
        return validator;
    }

}
