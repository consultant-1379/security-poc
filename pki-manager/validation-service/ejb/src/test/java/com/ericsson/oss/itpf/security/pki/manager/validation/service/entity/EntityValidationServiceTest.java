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

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@RunWith(MockitoJUnitRunner.class)
public class EntityValidationServiceTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityValidationService.class);

    @InjectMocks
    EntityValidationService entityValidationService;

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
    EntityOtpValidityPeriodValidator entityOtpValidityPeriodValidator;

    @Inject
    EntityCertificateExpiryNotificationDetailsValidator entityCertExpiryNotificationDetailsValidator;

    @Inject
    EntitySubjectUniqueIdentifierValidator entitySubjectUniqueIdentifierValidationService;
    ValidateItem validateItem = new ValidateItem();

    /**
     * Method to test create positive scenario
     */
    @Test
    public void testValidationService_create() {
        validateItem.setOperationType(OperationType.CREATE);

        final List<CommonValidator<Entity>> entityValidators = new LinkedList<CommonValidator<Entity>>();
        entityValidators.add(entityMissingMandatoryAttributesValidator);
        entityValidators.add(createEntityNameValidator);
        entityValidators.add(entityProfileValidator);
        entityValidators.add(entityKeyGenerationAlgorithmValidator);
        entityValidators.add(entitySubjectAndSANValidator);
        entityValidators.add(entityCategoryValidator);
        entityValidators.add(entityCertExpiryNotificationDetailsValidator);
        entityValidators.add(entityOtpValidityPeriodValidator);
        entityValidators.add(entitySubjectUniqueIdentifierValidationService);
        Assert.assertEquals(entityValidators, entityValidationService.getValidators(validateItem));
    }

    /**
     * Method to test update positive scenario
     */
    @Test
    public void testValidationService_update() {
        validateItem.setOperationType(OperationType.UPDATE);

        final List<CommonValidator<Entity>> entityValidators = new LinkedList<CommonValidator<Entity>>();
        entityValidators.add(entityMissingMandatoryAttributesValidator);
        entityValidators.add(updateEntityNameValidator);
        entityValidators.add(entityProfileValidator);
        entityValidators.add(entityKeyGenerationAlgorithmValidator);
        entityValidators.add(entitySubjectAndSANValidator);
        entityValidators.add(entityCategoryValidator);
        entityValidators.add(entityCertExpiryNotificationDetailsValidator);
        entityValidators.add(entityOtpValidityPeriodValidator);
        entityValidators.add(entitySubjectUniqueIdentifierValidationService);
        Assert.assertEquals(entityValidators, entityValidationService.getValidators(validateItem));
    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidationService_InvalidOperationType() {
        validateItem.setOperationType(OperationType.DELETE);

        final List<CommonValidator<Entity>> entityValidators = new LinkedList<CommonValidator<Entity>>();
        entityValidators.add(entityMissingMandatoryAttributesValidator);
        entityValidators.add(updateEntityNameValidator);
        entityValidators.add(entityProfileValidator);
        entityValidators.add(entityKeyGenerationAlgorithmValidator);
        entityValidators.add(entitySubjectAndSANValidator);
        entityValidators.add(entityCategoryValidator);
        entityValidators.add(entityOtpValidityPeriodValidator);
        entityValidators.add(entitySubjectUniqueIdentifierValidationService);
        Assert.assertEquals(entityValidators, entityValidationService.getValidators(validateItem));
    }

}
