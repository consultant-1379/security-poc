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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * This interface is used to validate any object.
 * 
 */
public interface CommonValidator<ModelType> {
    /**
     * This method is used for valdiate operation.
     * 
     * @param object
     *            {@link TrustProfile}/ {@link EntityProfile} / {@link CertificateProfile}/ {@link CAEntity}/ {@link Entity}/ {@link CertificateProfile}/ {@link CertificateProfile} that is to be
     *            persisted.
     * 
     * @throws ValidationException
     *             Thrown when any validation error occurs.
     */
    <ValidationException extends PKIBaseException> void validate(ModelType object) throws ValidationException;
}
