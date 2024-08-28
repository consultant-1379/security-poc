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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import java.util.Set;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.AbstractEntityValidator;

/**
 * Validates Certificate Expiry Notification Details for CA Entity
 * 
 * @author tcsviku
 * 
 */
public class CaEntityCertificateExpiryNotificationDetailsValidator extends AbstractEntityValidator implements CommonValidator<CAEntity> {
    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        final Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = caEntity.getCertificateExpiryNotificationDetails();
        if (!ValidationUtils.isNullOrEmpty(certificateExpiryNotificationDetails)) {
            validateCertificateExpiryNotificationDetails(caEntity.getCertificateExpiryNotificationDetails());
        }
    }

    /**
     * This method calls the {@link EntitiesPersistenceHandlerFactory} to get the appropriate {@link EntitiesPersistenceHandler} instance ( {@link CAEntityPersistenceHandler} ).
     * 
     * @return instance of {@link EntitiesPersistenceHandler} ( {@link CAEntityPersistenceHandler} ).
     * 
     */
    @Override
    protected EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler() {
        return entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY);
    }

}
