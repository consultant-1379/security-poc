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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.profile;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CAIssuerValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CertificateProfileExtensionsValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CertificateProfileKeyGenerationAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CertificateProfileSignatureAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CertificateValidityValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CertificateVersionValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CreateCertificateProfileNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.IssuerUniqueIdentifierValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.NonCAIssuerValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.SkewCertificateTimeValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.SubjectCapabilitiesValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.UpdateCertificateProfileNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@SuppressWarnings("PMD.TooManyFields")
@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileValidationServiceTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateProfileValidationService.class);

    @InjectMocks
    CertificateProfileValidationService certificateProfileValidationService;

    @Mock
    CreateCertificateProfileNameValidator createCertificateProfileNameValidator;

    @Mock
    UpdateCertificateProfileNameValidator updateCertificateProfileNameValidator;

    @Mock
    CertificateVersionValidator certificateVersionValidator;

    @Mock
    CertificateValidityValidator certificateValidityValidator;

    @Mock
    CertificateProfileSignatureAlgorithmValidator certificateProfileSignatureAlgorithmValidator;

    @Mock
    CertificateProfileKeyGenerationAlgorithmValidator certificateProfileKeyGenerationAlgorithmValidator;

    @Mock
    IssuerUniqueIdentifierValidator certificateProfileIssuerUniqueIdentifierValidator;

    @Mock
    SkewCertificateTimeValidator certificateProfileSkewCertificateTimeValidator;

    @Mock
    SubjectCapabilitiesValidator certificateProfileSubjectCapabilitiesValidator;

    @Mock
    CertificateProfileExtensionsValidator certificateProfileCertificateExtensionsValidator;

    @Mock
    CAIssuerValidator caIssuerValidator;

    @Mock
    NonCAIssuerValidator nonCAIssuerValidator;

    CertificateProfile certificateProfile = new CertificateProfile();

    ValidateItem validateItem = new ValidateItem();
    List<CommonValidator<CertificateProfile>> certificateProfileValidators;

    @Before
    public void setUp() {

        validateItem.setOperationType(OperationType.CREATE);
    }

    /**
     * Method to test create positive scenario
     */
    @Test
    public void testValidationService_create_forCAEntity() {
        validateItem.setOperationType(OperationType.CREATE);
        certificateProfileValidators = new ArrayList<CommonValidator<CertificateProfile>>();
        certificateProfileValidators.add(createCertificateProfileNameValidator);
        certificateProfileValidators.add(certificateVersionValidator);
        certificateProfileValidators.add(certificateValidityValidator);
        certificateProfileValidators.add(caIssuerValidator);
        certificateProfileValidators.add(certificateProfileSignatureAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileKeyGenerationAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileIssuerUniqueIdentifierValidator);
        certificateProfileValidators.add(certificateProfileCertificateExtensionsValidator);
        certificateProfileValidators.add(certificateProfileSkewCertificateTimeValidator);
        certificateProfileValidators.add(certificateProfileSubjectCapabilitiesValidator);

        certificateProfile.setForCAEntity(Boolean.TRUE);
        validateItem.setItem(certificateProfile);
        Assert.assertEquals(certificateProfileValidators, certificateProfileValidationService.getValidators(validateItem));
    }

    /**
     * Method to test create positive scenario
     */
    @Test
    public void testValidationService_create_nonCAEntity() {
        validateItem.setOperationType(OperationType.CREATE);
        certificateProfileValidators = new ArrayList<CommonValidator<CertificateProfile>>();
        certificateProfileValidators.add(createCertificateProfileNameValidator);
        certificateProfileValidators.add(certificateVersionValidator);
        certificateProfileValidators.add(certificateValidityValidator);
        certificateProfileValidators.add(nonCAIssuerValidator);
        certificateProfileValidators.add(certificateProfileSignatureAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileKeyGenerationAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileIssuerUniqueIdentifierValidator);
        certificateProfileValidators.add(certificateProfileCertificateExtensionsValidator);
        certificateProfileValidators.add(certificateProfileSkewCertificateTimeValidator);
        certificateProfileValidators.add(certificateProfileSubjectCapabilitiesValidator);

        certificateProfile.setForCAEntity(Boolean.FALSE);
        validateItem.setItem(certificateProfile);
        Assert.assertEquals(certificateProfileValidators, certificateProfileValidationService.getValidators(validateItem));
    }

    /**
     * Method to test update positive scenario
     */
    @Test
    public void testValidationService_update_forCAEntity() {
        validateItem.setOperationType(OperationType.UPDATE);
        certificateProfileValidators = new ArrayList<CommonValidator<CertificateProfile>>();
        certificateProfileValidators.add(updateCertificateProfileNameValidator);
        certificateProfileValidators.add(certificateVersionValidator);
        certificateProfileValidators.add(certificateValidityValidator);
        certificateProfileValidators.add(caIssuerValidator);
        certificateProfileValidators.add(certificateProfileSignatureAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileKeyGenerationAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileIssuerUniqueIdentifierValidator);
        certificateProfileValidators.add(certificateProfileCertificateExtensionsValidator);
        certificateProfileValidators.add(certificateProfileSkewCertificateTimeValidator);
        certificateProfileValidators.add(certificateProfileSubjectCapabilitiesValidator);

        certificateProfile.setForCAEntity(Boolean.TRUE);
        validateItem.setItem(certificateProfile);
        Assert.assertEquals(certificateProfileValidators, certificateProfileValidationService.getValidators(validateItem));
    }

    /**
     * Method to test update positive scenario
     */
    @Test
    public void testValidationService_update_nonCAEntity() {
        validateItem.setOperationType(OperationType.UPDATE);
        certificateProfileValidators = new ArrayList<CommonValidator<CertificateProfile>>();
        certificateProfileValidators.add(updateCertificateProfileNameValidator);
        certificateProfileValidators.add(certificateVersionValidator);
        certificateProfileValidators.add(certificateValidityValidator);
        certificateProfileValidators.add(nonCAIssuerValidator);
        certificateProfileValidators.add(certificateProfileSignatureAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileKeyGenerationAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileIssuerUniqueIdentifierValidator);
        certificateProfileValidators.add(certificateProfileCertificateExtensionsValidator);
        certificateProfileValidators.add(certificateProfileSkewCertificateTimeValidator);
        certificateProfileValidators.add(certificateProfileSubjectCapabilitiesValidator);

        certificateProfile.setForCAEntity(Boolean.FALSE);
        validateItem.setItem(certificateProfile);
        Assert.assertEquals(certificateProfileValidators, certificateProfileValidationService.getValidators(validateItem));
    }

    /**
     * Method to test negative scenario
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidationService_InvalidOperationType() {
        validateItem.setOperationType(OperationType.DELETE);
        certificateProfileValidators = new ArrayList<CommonValidator<CertificateProfile>>();
        certificateProfileValidators.add(updateCertificateProfileNameValidator);
        certificateProfileValidators.add(certificateVersionValidator);
        certificateProfileValidators.add(certificateValidityValidator);
        certificateProfileValidators.add(caIssuerValidator);
        certificateProfileValidators.add(certificateProfileSignatureAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileKeyGenerationAlgorithmValidator);
        certificateProfileValidators.add(certificateProfileIssuerUniqueIdentifierValidator);
        certificateProfileValidators.add(certificateProfileCertificateExtensionsValidator);
        certificateProfileValidators.add(certificateProfileSkewCertificateTimeValidator);
        certificateProfileValidators.add(certificateProfileSubjectCapabilitiesValidator);

        Assert.assertEquals(certificateProfileValidators, certificateProfileValidationService.getValidators(validateItem));
    }

}
