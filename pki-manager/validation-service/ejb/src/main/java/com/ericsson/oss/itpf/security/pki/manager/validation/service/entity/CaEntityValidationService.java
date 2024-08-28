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

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.BaseValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/*
 * This class is used to get the respective validators to validate a caentity.
 *
 * @author xtelsow
 */
@ServiceQualifier(ItemType.CA_ENTITY)
public class CaEntityValidationService extends BaseValidationService<CAEntity> {

    @Inject
    CreateCaEntityNameValidator createCaEntityNameValidator;

    @Inject
    UpdateCaEntityNameValidator updateCaEntityNameValidator;

    @Inject
    CAEntityMissingMandatoryAttributesValidator caEntityMissingMandatoryAttributesParamsValidator;

    @Inject
    CaEntityProfileValidator caEntityProfileValidator;

    @Inject
    CaEntityKeyGenerationAlgorithm caEntityKeyGenerationAlgorithmValidator;

    @Inject
    CaEntitySubjectValidator caEntitySubjectValidator;

    @Inject
    CaEntitySANValidator caEntitySANValidator;

    @Inject
    CrlGenerationInfoValidator crlGenerationInfoValidator;

    @Inject
    CaEntityCertificateExpiryNotificationDetailsValidator caEntityCertExpiryNotificationDetailsValidator;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.validation.common.profile. validation .service.CommonValidationService#getValidators(com.ericsson.oss.
     * itpf.security.pki.manager.validation.common.ItemType)
     */
    @Override
    public List<CommonValidator<CAEntity>> getValidators(final ValidateItem validateItem) {

        final List<CommonValidator<CAEntity>> caEntityValidators = new LinkedList<CommonValidator<CAEntity>>();
        caEntityValidators.add(caEntityMissingMandatoryAttributesParamsValidator);
        caEntityValidators.add(getEntityNameValidator(validateItem.getOperationType()));
        caEntityValidators.add(caEntityProfileValidator);
        caEntityValidators.add(caEntityKeyGenerationAlgorithmValidator);
        caEntityValidators.add(caEntitySubjectValidator);
        caEntityValidators.add(caEntitySANValidator);
        caEntityValidators.add(crlGenerationInfoValidator);
        caEntityValidators.add(caEntityCertExpiryNotificationDetailsValidator);
        return caEntityValidators;
    }

    /**
     * This method returns the respective caentity validator class for given operationType i.e. either create or update
     * 
     * @param operationType
     * @return CommonValidator<CAEntity>
     */
    private CommonValidator<CAEntity> getEntityNameValidator(final OperationType operationType) {
        CommonValidator<CAEntity> validator = null;
        switch (operationType) {
        case CREATE:
            validator = createCaEntityNameValidator;
            break;
        case UPDATE:
            validator = updateCaEntityNameValidator;
            break;
        default:
            throw new IllegalArgumentException("Invalid Operation Type");
        }
        return validator;
    }

}