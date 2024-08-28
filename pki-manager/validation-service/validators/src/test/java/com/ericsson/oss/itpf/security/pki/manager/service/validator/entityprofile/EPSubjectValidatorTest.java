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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@RunWith(MockitoJUnitRunner.class)
public class EPSubjectValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EPSubjectValidator.class);

    @InjectMocks
    EPSubjectValidator epSubjectValidator;

    @Mock
    SubjectValidator subjectValidator;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    CommonProfileHelper commonProfileHelper;

    private EntityProfile entityProfile = null;
    private CertificateProfile certificateProfile = null;
    private TrustProfileData trustProfileData = null;
    private String certificateProfileName;
    private EntityProfileSetUpData entityProfileSetUpToTest;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        entityProfileSetUpToTest = new EntityProfileSetUpData();
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        certificateProfileName = entityProfile.getCertificateProfile().getName();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        final CertificateProfileData certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();

        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions());
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions()));
        trustProfileData = new TrustProfileData();
        trustProfileData.setName("TrustProfile_1");
    }

    @Test
    public void testCreateProfileWithValidSubject() {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        when(subjectValidator.validate(entityProfile.getSubject())).thenReturn(true);
        epSubjectValidator.validate(entityProfile);

    }

    /**
     * Method to test Invalid SujectAltNameFields present in EntityProfile.
     *
     * @throws Exception
     */
    @Test(expected = InvalidSubjectException.class)
    public void testValidateCreate_InvalidSubject() throws Exception {

        entityProfile = entityProfileSetUpToTest.setEntityProfileWithoutSubject(entityProfile);

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        certificateProfile.setForCAEntity(true);

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        when(subjectValidator.validate(entityProfile.getSubject())).thenReturn(false);
        epSubjectValidator.validate(entityProfile);

    }

    /**
     * Method to test Invalid SujectAltNameFields present in EntityProfile.
     *
     * @throws Exception
     */
    @Test(expected = InvalidSubjectException.class)
    public void testValidateCreate_InvalidSubjectFieldType() throws Exception {

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.STREET_ADDRESS);
        subjectField.setValue("surname_1");
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        certificateProfile.getSubjectCapabilities().setSubjectFields(subjectFields);

        certificateProfile.setForCAEntity(true);

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        when(subjectValidator.validate(entityProfile.getSubject())).thenReturn(false);
        epSubjectValidator.validate(entityProfile);

    }

    /**
     * Method to test validate method with null Subject Value in EntityProfile.
     *
     */
    @Test(expected = InvalidSubjectException.class)
    public void testCreateProfileWithNullSubject() {

        certificateProfile.setForCAEntity(true);
        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        entityProfile.setSubject(null);

        epSubjectValidator.validate(entityProfile);

    }

    /**
     * Method to test validate method with null Subject value in EntityProfile and forCaEntityField is set as false in CertificateProfile.
     *
     */
    @Test
    public void testCreateProfileWithNullSubjAndWithoutCaEntity() {

        certificateProfile.setForCAEntity(false);
        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        entityProfile.setSubject(null);

        Assert.assertEquals(epSubjectValidator.validate(entityProfile), false);

    }
}
