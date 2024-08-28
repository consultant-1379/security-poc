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

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@RunWith(MockitoJUnitRunner.class)
public class EntityProfileValidationServiceTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EntityProfileValidationService.class);

    @InjectMocks
    EntityProfileValidationService entityProfileValidationService;

    @Mock
    CreateEntityProfileNameValidator createEntityProfileNameValidator;

    @Mock
    UpdateEntityProfileNameValidator updateEntityProfileNameValidator;

    @Mock
    EPMissingMandatoryAttributesValidator epMissingMandatoryAttributesValidator;

    @Mock
    KeyUsageExtensionValidator epKeyUsageExtensionValidator;

    @Mock
    ExtendedKeyUsageValidator epExtendedKeyUsageValidator;

    @Mock
    EPKeyGenerationAlgorithmValidator epKeyGenerationAlgorithmValidator;

    @Mock
    EntityCategoryNameValidator entityCategoryNamesValidator;

    @Mock
    TrustProfileNamesValidator trustProfileNamesValidator;

    @Mock
    SubjectAndSubjectAltNameValidator subjectAndSubjectAltNameValidator;

    @Mock
    EPSubjectUniqueIdentifierValidator subjectUniqueIdentifierValidationService;

    ValidateItem validateItem = new ValidateItem();

    /**
     * Method to test create positive scenario
     */
    @Test
    public void testValidationService_create() {
        validateItem.setOperationType(OperationType.CREATE);
        final List<CommonValidator<EntityProfile>> entityProfileValidators = new ArrayList<CommonValidator<EntityProfile>>();
        entityProfileValidators.add(createEntityProfileNameValidator);
        entityProfileValidators.add(epMissingMandatoryAttributesValidator);
        entityProfileValidators.add(subjectAndSubjectAltNameValidator);
        entityProfileValidators.add(epKeyUsageExtensionValidator);
        entityProfileValidators.add(epExtendedKeyUsageValidator);
        entityProfileValidators.add(epKeyGenerationAlgorithmValidator);
        entityProfileValidators.add(trustProfileNamesValidator);
        entityProfileValidators.add(entityCategoryNamesValidator);
        entityProfileValidators.add(subjectUniqueIdentifierValidationService);
        Assert.assertEquals(entityProfileValidators, entityProfileValidationService.getValidators(validateItem));
    }

    /**
     * Method to test update positive scenario
     */
    @Test
    public void testValidationService_update() {
        validateItem.setOperationType(OperationType.UPDATE);
        final List<CommonValidator<EntityProfile>> entityProfileValidators = new ArrayList<CommonValidator<EntityProfile>>();
        entityProfileValidators.add(updateEntityProfileNameValidator);
        entityProfileValidators.add(epMissingMandatoryAttributesValidator);
        entityProfileValidators.add(subjectAndSubjectAltNameValidator);
        entityProfileValidators.add(epKeyUsageExtensionValidator);
        entityProfileValidators.add(epExtendedKeyUsageValidator);
        entityProfileValidators.add(epKeyGenerationAlgorithmValidator);
        entityProfileValidators.add(trustProfileNamesValidator);
        entityProfileValidators.add(entityCategoryNamesValidator);
        entityProfileValidators.add(subjectUniqueIdentifierValidationService);

        Assert.assertEquals(entityProfileValidators, entityProfileValidationService.getValidators(validateItem));
    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidationService_InvalidOperationType() {
        validateItem.setOperationType(OperationType.DELETE);
        final List<CommonValidator<EntityProfile>> entityProfileValidators = new ArrayList<CommonValidator<EntityProfile>>();
        entityProfileValidators.add(updateEntityProfileNameValidator);
        entityProfileValidators.add(epMissingMandatoryAttributesValidator);
        entityProfileValidators.add(subjectAndSubjectAltNameValidator);
        entityProfileValidators.add(epKeyUsageExtensionValidator);
        entityProfileValidators.add(epExtendedKeyUsageValidator);
        entityProfileValidators.add(epKeyGenerationAlgorithmValidator);
        entityProfileValidators.add(trustProfileNamesValidator);
        entityProfileValidators.add(entityCategoryNamesValidator);
        entityProfileValidators.add(subjectUniqueIdentifierValidationService);

        Assert.assertEquals(entityProfileValidators, entityProfileValidationService.getValidators(validateItem));
    }
}
