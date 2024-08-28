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

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

/**
 * This is an interface which provides API for validating the items.
 * 
 * @param validateItem
 *            {@link ValidateItem} containing object, operationType and ItemType.
 * 
 * @throws ValidationException
 *             thrown when any validation exceptions occur.
 */
public interface CommonValidationService {
    <ValidationException extends PKIBaseException> void validate(ValidateItem validateItem) throws ValidationException;
}
