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
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.BaseValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/*
 * This class is used to get the respective validators to validate a entity.
 *
 * @author xtelsow
 */
@ServiceQualifier(ItemType.ENTITY)
public class EntityValidationService extends BaseValidationService<Entity> {
    @Inject
    CreateEntityNameValidator createEntityNameValidator;

    @Inject
    UpdateEntityNameValidator updateEntityNameValidator;

    @Inject
    EntityMissingMandatoryAttributesValidator entityMissingMandatoryAttributesValidator;

    @Inject
    EntityProfileValidator entityProfileValidator;

    @Inject
    EntityKeyGenerationAlgorithmValidator entityKeyGenerationAlgorithmValidator;

    @Inject
    EntitySubjectAndSANValidator entitySubjectAndSANValidator;

    @Inject
    EntityCategoryValidator entityCategoryValidator;

    @Inject
    EntityCertificateExpiryNotificationDetailsValidator entityCertExpiryNotificationDetailsValidator;

    @Inject
    EntityOtpValidityPeriodValidator entityOtpValidityPeriodValidator;

    @Inject
    EntitySubjectUniqueIdentifierValidator entitySubjectUniqueIdentifierValidationService;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.validation.common.profile.validation.service.CommonValidationService#getValidators(com.ericsson.oss.
     * itpf.security.pki.manager.validation.common.ItemType)
     */
    @Override
    public List<CommonValidator<Entity>> getValidators(final ValidateItem validateItem) {

        final List<CommonValidator<Entity>> entityValidators = new LinkedList<CommonValidator<Entity>>();
        entityValidators.add(entityMissingMandatoryAttributesValidator);
        entityValidators.add(getEntityNameValidator(validateItem.getOperationType()));
        entityValidators.add(entityProfileValidator);
        entityValidators.add(entityKeyGenerationAlgorithmValidator);
        entityValidators.add(entitySubjectAndSANValidator);
        entityValidators.add(entityCategoryValidator);
        entityValidators.add(entityCertExpiryNotificationDetailsValidator);
        entityValidators.add(entityOtpValidityPeriodValidator);
        entityValidators.add(entitySubjectUniqueIdentifierValidationService);
        return entityValidators;
    }

    /**
     * This method returns the respective entity validator class for given operationType i.e. either create or update
     * 
     * @param operationType
     * @return CommonValidator<Entity>
     */
    private CommonValidator<Entity> getEntityNameValidator(final OperationType operationType) {
        CommonValidator<Entity> validator = null;
        switch (operationType) {
        case CREATE:
            validator = createEntityNameValidator;
            break;
        case UPDATE:
            validator = updateEntityNameValidator;
            break;
        default:
            throw new IllegalArgumentException("Invalid Operation Type");
        }
        return validator;
    }
}
