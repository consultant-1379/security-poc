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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.common;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

/**
 * This class is used to get all the validator's under particular service and validate them.
 * 
 * 
 */
public abstract class BaseValidationService<T> implements CommonValidationService {

    @Inject
    Logger logger;

    /**
     * Used to get validators for corresponding ProfileService
     * 
     * @param validateItem
     *            Validate item object.
     * @return List<CommonValidator<T>>
     */
    public abstract List<CommonValidator<T>> getValidators(ValidateItem validateItem);

    /**
     * @param validateItem
     *            Validate item object.
     * 
     * @throws ValidationException
     *             For any validation exceptions.
     */
    public <ValidationException extends PKIBaseException> void validate(final ValidateItem validateItem) throws ValidationException {
        final List<CommonValidator<T>> commonValidators = getValidators(validateItem);

        logger.debug("Validators under {} : {}", validateItem.getItemType(), commonValidators);

        for (final CommonValidator<T> validator : commonValidators) {
            validator.validate((T) validateItem.getItem());
        }
    }
}