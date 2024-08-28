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

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@RunWith(MockitoJUnitRunner.class)
public class CaEntityValidationServiceTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(CaEntityValidationService.class);

    @InjectMocks
    CaEntityValidationService caEntityValidationService;

    @Mock
    CreateCaEntityNameValidator createCaEntityNameValidator;

    @Mock
    UpdateCaEntityNameValidator updateCaEntityNameValidator;

    @Mock
    CAEntityMissingMandatoryAttributesValidator caEntityMissingMandatoryAttributesParamsValidator;

    @Mock
    CaEntityProfileValidator caEntityProfileValidator;

    @Mock
    CaEntityKeyGenerationAlgorithm caEntityKeyGenerationAlgorithmValidator;

    @Mock
    CaEntitySubjectValidator caEntitySubjectValidator;

    @Mock
    CaEntitySANValidator caEntitySANValidator;

    @Mock
    CrlGenerationInfoValidator crlGenerationInfoValidator;

    @Mock
    CaEntityCertificateExpiryNotificationDetailsValidator caEntityCertExpiryNotificationDetailsValidator;

    ValidateItem validateItem = new ValidateItem();

    /**
     * Method to test create positive scenario
     */
    @Test
    public void testValidationService_create() {
        validateItem.setOperationType(OperationType.CREATE);
        final List<CommonValidator<CAEntity>> caEntityValidators = new ArrayList<CommonValidator<CAEntity>>();
        caEntityValidators.add(caEntityMissingMandatoryAttributesParamsValidator);
        caEntityValidators.add(createCaEntityNameValidator);
        caEntityValidators.add(caEntityProfileValidator);
        caEntityValidators.add(caEntityKeyGenerationAlgorithmValidator);
        caEntityValidators.add(caEntitySubjectValidator);
        caEntityValidators.add(caEntitySANValidator);
        caEntityValidators.add(crlGenerationInfoValidator);
        caEntityValidators.add(caEntityCertExpiryNotificationDetailsValidator);
        Assert.assertEquals(caEntityValidators, caEntityValidationService.getValidators(validateItem));
    }

    /**
     * Method to test update positive scenario
     */
    @Test
    public void testValidationService_update() {
        validateItem.setOperationType(OperationType.UPDATE);
        final List<CommonValidator<CAEntity>> caEntityValidators = new ArrayList<CommonValidator<CAEntity>>();
        caEntityValidators.add(caEntityMissingMandatoryAttributesParamsValidator);
        caEntityValidators.add(updateCaEntityNameValidator);
        caEntityValidators.add(caEntityProfileValidator);
        caEntityValidators.add(caEntityKeyGenerationAlgorithmValidator);
        caEntityValidators.add(caEntitySubjectValidator);
        caEntityValidators.add(caEntitySANValidator);
        caEntityValidators.add(crlGenerationInfoValidator);
        caEntityValidators.add(caEntityCertExpiryNotificationDetailsValidator);
        Assert.assertEquals(caEntityValidators, caEntityValidationService.getValidators(validateItem));
    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidationService_InvalidOperationType() {
        validateItem.setOperationType(OperationType.DELETE);
        final List<CommonValidator<CAEntity>> caEntityValidators = new ArrayList<CommonValidator<CAEntity>>();
        caEntityValidators.add(updateCaEntityNameValidator);
        caEntityValidators.add(caEntityMissingMandatoryAttributesParamsValidator);
        caEntityValidators.add(caEntityProfileValidator);
        caEntityValidators.add(caEntityKeyGenerationAlgorithmValidator);
        caEntityValidators.add(caEntitySANValidator);
        caEntityValidators.add(caEntitySubjectValidator);
        caEntityValidators.add(crlGenerationInfoValidator);
        Assert.assertEquals(caEntityValidators, caEntityValidationService.getValidators(validateItem));
    }
}
