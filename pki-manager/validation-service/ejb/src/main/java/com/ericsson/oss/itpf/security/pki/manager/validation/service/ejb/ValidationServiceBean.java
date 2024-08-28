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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.ejb;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.ValidationServiceManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.CommonValidationService;

/*
 * This class is used to get the respective validation service and validate.
 */
@Stateless
public class ValidationServiceBean implements ValidationService {

    @Inject
    ValidationServiceManager validationServiceManager;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final ValidateItem validateItem) {

        CommonValidationService commonValidationService = null;

        switch (validateItem.getItemType()) {

        case CERTIFICATE_PROFILE:
            commonValidationService = validationServiceManager.getCertificateProfileValidationService();
            break;

        case ENTITY_PROFILE:
            commonValidationService = validationServiceManager.getEntityProfileValidationService();
            break;

        case TRUST_PROFILE:
            commonValidationService = validationServiceManager.getTrustProfileValidationService();
            break;

        case CA_ENTITY:
            commonValidationService = validationServiceManager.getCaEntityValidationService();
            break;

        case ENTITY:
            commonValidationService = validationServiceManager.getEntityValidationService();
            break;

        case X509CERTIFICATE:
            commonValidationService = validationServiceManager.getX509CertificateValidationService();
            break;

        case GENERATE_CSR:
            commonValidationService = validationServiceManager.getExportCSRValidationService();
            break;

        case ENTITY_OTP:
            commonValidationService = validationServiceManager.getOtpValidationService();
            break;
        default:
            throw new IllegalArgumentException("Invalid Item Type  " + validateItem.getItemType());
        }

        commonValidationService.validate(validateItem);
    }

}
