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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.certificate;

import java.util.LinkedList;
import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.csr.CAValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.qualifiers.ServiceQualifier;

/**
 * This class is used to fetch all the validators based on the user request.
 *
 * @author tcsramc
 *
 */
@ServiceQualifier(ItemType.GENERATE_CSR)
public class GenerateCSRValidationService extends CertificateValidationService<CAValidationInfo> {

    @Inject
    CAValidator cAValidator;

    /**
     * This method is used to get validators of corresponding Validation Service.
     *
     * @param validateItem
     *            Validate item object.
     *
     */

    @Override
    public List<CommonValidator<CAValidationInfo>> getValidators(final ValidateItem validateItem) {
        final List<CommonValidator<CAValidationInfo>> exportCSRValidators = new LinkedList<CommonValidator<CAValidationInfo>>();
        exportCSRValidators.add(cAValidator);
        return exportCSRValidators;

    }
}
