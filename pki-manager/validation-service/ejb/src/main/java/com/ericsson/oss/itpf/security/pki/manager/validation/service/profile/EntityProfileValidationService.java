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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.profile;

import java.util.LinkedList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.CreateEntityProfileNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.EPKeyGenerationAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.EPMissingMandatoryAttributesValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.EPSubjectUniqueIdentifierValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.EntityCategoryNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.ExtendedKeyUsageValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.KeyUsageExtensionValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.SubjectAndSubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.TrustProfileNamesValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.UpdateEntityProfileNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.BaseValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/*
 * This class is used to get the respective validators to validate an entityprofile.
 */

@ServiceQualifier(ItemType.ENTITY_PROFILE)
public class EntityProfileValidationService extends BaseValidationService<EntityProfile> {

    @Inject
    CreateEntityProfileNameValidator createEntityProfileNameValidator;

    @Inject
    UpdateEntityProfileNameValidator updateEntityProfileNameValidator;

    @Inject
    EPMissingMandatoryAttributesValidator epMissingMandatoryAttributesValidator;

    @Inject
    SubjectAndSubjectAltNameValidator subjectAndSubjectAltNameValidator;

    @Inject
    KeyUsageExtensionValidator epKeyUsageExtensionValidator;

    @Inject
    ExtendedKeyUsageValidator epExtendedKeyUsageValidator;

    @Inject
    EPKeyGenerationAlgorithmValidator epKeyGenerationAlgorithmValidator;

    @Inject
    EntityCategoryNameValidator entityCategoryNamesValidator;

    @Inject
    TrustProfileNamesValidator trustProfileNamesValidator;

    @Inject
    EPSubjectUniqueIdentifierValidator subjectUniqueIdentifierValidationService;

    @Inject
    Logger logger;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.validation.common.profile. validation .service.CommonValidationService#getValidators(com.ericsson.oss.
     * itpf.security.pki.manager.validation.common.ItemType)
     */
    @Override
    public List<CommonValidator<EntityProfile>> getValidators(final ValidateItem validateItem) {

        final String validateItemOperationType = validateItem.getOperationType().name();
        final List<CommonValidator<EntityProfile>> entityProfileValidators = new LinkedList<CommonValidator<EntityProfile>>();

        entityProfileValidators.add(getProfileNameValidator(validateItem.getOperationType()));
        entityProfileValidators.add(epMissingMandatoryAttributesValidator);
        entityProfileValidators.add(subjectAndSubjectAltNameValidator);
        entityProfileValidators.add(epKeyUsageExtensionValidator);
        entityProfileValidators.add(epExtendedKeyUsageValidator);
        entityProfileValidators.add(epKeyGenerationAlgorithmValidator);
        entityProfileValidators.add(trustProfileNamesValidator);
        entityProfileValidators.add(entityCategoryNamesValidator);
        entityProfileValidators.add(subjectUniqueIdentifierValidationService);

        logger.debug("Completed validating {} Entity Profile", validateItemOperationType);
        return entityProfileValidators;
    }

    private CommonValidator<EntityProfile> getProfileNameValidator(final OperationType operationType) {
        CommonValidator<EntityProfile> validator = null;
        switch (operationType) {
        case CREATE:
            validator = createEntityProfileNameValidator;
            break;

        case UPDATE:
            validator = updateEntityProfileNameValidator;
            break;

        default:
            throw new IllegalArgumentException("Invalid Operation Type");
        }

        return validator;
    }
}