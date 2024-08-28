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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.upgrade.SyncMismatchEntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPNotSetException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.EntityManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@Stateless
public class EntityManagementLocalServiceBean implements EntityManagementLocalService {

    @Inject
    EntitiesManager entitiesManager;

    @Inject
    SyncMismatchEntitiesPersistenceHandler syncMismatchEntitiesPersistenceHandler;

    @Inject
    ValidationServiceUtils validateServiceUtils;

    @Inject
    ValidationService validationService;

    @Inject
    Logger logger;

    @Override
    public String getOTP(final String entityName) throws EntityNotFoundException, EntityServiceException, OTPExpiredException, OTPNotSetException {

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);

        final Entity entity = new Entity();
        entity.setEntityInfo(entityInfo);

        final ValidateItem otpValidateItem = validateServiceUtils.generateOtpValidateItem(ItemType.ENTITY_OTP, OperationType.VALIDATE, entity);
        validationService.validate(otpValidateItem);

        return entitiesManager.getOtp(entity);

    }

    @Override
    public boolean isOTPValid(final String entityName, final String otp) throws EntityNotFoundException, EntityServiceException, OTPExpiredException {
        return entitiesManager.isOTPValid(entityName, otp);
    }

    @Override
    public Entity getEntity(final String entitySubjectDN, final String issuerDN) throws AlgorithmNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException {
        return entitiesManager.getEntity(entitySubjectDN, issuerDN);
    }

    @Override
    public void syncMismatchEntities() {
        try {
            syncMismatchEntitiesPersistenceHandler.syncMismatchEntities();
        } catch (final Exception exception) {
            logger.error("Error occured during Handling Inconsistent data between subject_identification_details table and entity table  ", exception.getMessage());

        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public <T extends AbstractEntity> void deletePkiManagerEntity(final String entityName)
            throws EntityAlreadyDeletedException, EntityNotFoundException, EntityInUseException, EntityServiceException, InvalidEntityAttributeException {
        entitiesManager.deletePkiManagerEntity(entityName);
    }
}
