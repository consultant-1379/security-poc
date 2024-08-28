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
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateValidationServiceTest {

    @InjectMocks
    X509CertificateValidationService x509CertificateValidationService;

    @Test
    public void testGetValidators() {
        ValidateItem validateItem = new ValidateItem();
        validateItem.setItemType(ItemType.CA_ENTITY);
        validateItem.setOperationType(OperationType.UPDATE);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.isForceImport();
        validateItem.setItem(cACertificateValidationInfo);
        validateItem.setSkipOptionalTests(true);

        x509CertificateValidationService.getValidators(validateItem);
    }

}
