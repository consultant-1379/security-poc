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

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.BaseValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/*
 * This class is used to get the respective validators to validate a trustprofile. 
 */
@ServiceQualifier(ItemType.TRUST_PROFILE)
public class TrustProfileValidationService extends BaseValidationService<TrustProfile> {

    @Inject
    private CreateTrustProfileNameValidator createTrustProfileNameValidator;

    @Inject
    private UpdateTrustProfileNameValidator updateTrustProfileValidator;

    @Inject
    private ExternalCAsValidator externalCAsValidator;

    @Inject
    private TrustCAChainsValidator trustCAChainsValidator;

    @Inject
    TrustProfileParamsValidator trustProfileParamsValidator;

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.validation.common.profile. validation .service.CommonValidationService#getValidators(com.ericsson.oss.
     * itpf.security.pki.manager.validation.common.ItemType)
     */
    @Override
    public List<CommonValidator<TrustProfile>> getValidators(final ValidateItem validateItem) {

        final List<CommonValidator<TrustProfile>> trustProfileValidators = new LinkedList<CommonValidator<TrustProfile>>();

        trustProfileValidators.add(getProfileNameValidator(validateItem.getOperationType()));
        trustProfileValidators.add(trustProfileParamsValidator);
        trustProfileValidators.add(trustCAChainsValidator);
        trustProfileValidators.add(externalCAsValidator);

        return trustProfileValidators;
    }

    private CommonValidator<TrustProfile> getProfileNameValidator(final OperationType operationType) {
        CommonValidator<TrustProfile> validator = null;
        switch (operationType) {
        case CREATE:
            validator = createTrustProfileNameValidator;
            break;
        case UPDATE:
            validator = updateTrustProfileValidator;
            break;
        default:
            throw new IllegalArgumentException("Invalid Operation Type");
        }
        return validator;
    }
}