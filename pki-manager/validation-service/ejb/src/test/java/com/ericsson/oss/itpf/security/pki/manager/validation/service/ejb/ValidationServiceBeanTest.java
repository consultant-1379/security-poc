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

import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.validation.service.ValidationServiceManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.common.CommonValidationService;

@RunWith(MockitoJUnitRunner.class)
public class ValidationServiceBeanTest {

    @InjectMocks
    private ValidationServiceBean validationServiceBean;

    @Mock
    private ValidationServiceManager validationServiceManager;

    @Mock
    private CommonValidationService commonValidationService;

    private ValidateItem validateItem;

    @Before
    public void setUp() {
        validateItem = new ValidateItem();
        validateItem.setOperationType(OperationType.CREATE);
    }

    @Test
    public void testValidationOfTrustProfile() {
        validateItem.setItemType(ItemType.TRUST_PROFILE);
        when(validationServiceManager.getTrustProfileValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
    }

    @Test
    public void testValidationOfEntityProfile() {
        validateItem.setItemType(ItemType.ENTITY_PROFILE);
        when(validationServiceManager.getEntityProfileValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidation_InvalidItemType() {
        validateItem.setItemType(ItemType.UNKNOWN);
        when(validationServiceManager.getEntityProfileValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
    }

    @Test
    public void testValidationOfEntity() {
        validateItem.setItemType(ItemType.ENTITY);
        when(validationServiceManager.getEntityValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
        Mockito.verify(validationServiceManager).getEntityValidationService();
    }

    @Test
    public void testValidationOfCaEntity() {
        validateItem.setItemType(ItemType.CA_ENTITY);
        when(validationServiceManager.getCaEntityValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
        Mockito.verify(validationServiceManager).getCaEntityValidationService();

    }

    @Test
    public void testValidationOfCertProfile() {
        validateItem.setItemType(ItemType.CERTIFICATE_PROFILE);
        when(validationServiceManager.getCertificateProfileValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
        Mockito.verify(validationServiceManager).getCertificateProfileValidationService();

    }

    @Test
    public void testValidationOfCertificate() {
        validateItem.setItemType(ItemType.X509CERTIFICATE);
        when(validationServiceManager.getX509CertificateValidationService()).thenReturn(commonValidationService);
        commonValidationService.validate(validateItem);
        validationServiceBean.validate(validateItem);
        Mockito.verify(validationServiceManager).getX509CertificateValidationService();

    }
}
