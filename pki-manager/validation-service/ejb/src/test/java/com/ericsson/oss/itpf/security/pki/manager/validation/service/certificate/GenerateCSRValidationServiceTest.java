/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.validation.service.certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.service.validator.csr.CAValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@RunWith(MockitoJUnitRunner.class)
public class GenerateCSRValidationServiceTest {

    @InjectMocks
    GenerateCSRValidationService generateCSRValidationService;

    @Mock
    CAValidator cAValidator;

    @Test
    public void testGetValidators() {
        ValidateItem validateItem = new ValidateItem();
        validateItem.setSkipOptionalTests(false);
        generateCSRValidationService.getValidators(validateItem);
    }

}
