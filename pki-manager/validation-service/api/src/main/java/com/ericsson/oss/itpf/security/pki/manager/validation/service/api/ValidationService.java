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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

/*
 This interface is used to validate all profiles, entities, algorithms.
 */
@EService
@Local
public interface ValidationService {

    /**
     * This method is used to validate any object sent in validateItem.
     * 
     * @param validateItem
     *            {@link ValidateItem} containing the object, operationType and ItemType.
     * 
     */
    <ValidationException extends PKIBaseException> void validate(ValidateItem validateItem);

}
