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

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.CommonProfileHelper;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;

@RunWith(MockitoJUnitRunner.class)
public class EPSubjectAltNameValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EPSubjectAltNameValidator.class);

    @InjectMocks
    EPSubjectAltNameValidator epSubjectAltNameValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    CommonProfileHelper commonProfileHelper;

    private EntityProfile entityProfile = null;
    private CertificateProfile certificateProfile = null;
    private TrustProfileData trustProfileData = null;
    private String certificateProfileName;
    private CertificateProfileSetUpData certificateProfileSetUpToTest;
    private EntityProfileSetUpData entityProfileSetUpToTest;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        entityProfileSetUpToTest = new EntityProfileSetUpData();
        certificateProfileSetUpToTest = new CertificateProfileSetUpData();
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
    public void testValidSubjectAltName() {

        entityProfile.setSubjectAltNameExtension(entityProfileSetUpToTest.getValidSAN());

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));

        subjectAltNameValidator.validate(entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields().get(0));
        epSubjectAltNameValidator.validate(entityProfile);

    }

    /**
     * Method to test Invalid SujectAltNameFields in CertificateProfile.
     *
     * @throws Exception
     */
    @Test
    public void testEP_EmptySubjectAltNameInCertProfile() throws Exception {

        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateExtensions_WithInvalidSubjectAltName());

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));

        epSubjectAltNameValidator.validate(entityProfile);

    }

    /**
     * Method to test Invalid SujectAltNameFieldType in CertificateProfile.
     *
     * @throws Exception
     */
    @Test
    public void testEP_EmptySubjectAltNameFieldTypeInCertProfile() throws Exception {

        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateExtensions_WithInvalidSubjectAltName());

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenReturn(certificateProfileSetUpToTest.getCertificateExtensions(certificateProfile));

        epSubjectAltNameValidator.validate(entityProfile);

    }

    /**
     * Method to test Invalid certificate extensions present in EntityProfile.
     *
     * @throws Exception
     */
    @Test(expected = CertificateExtensionException.class)
    public void testEP_InvalidCertificateExtensions() throws Exception {

        certificateProfile.setCertificateExtensions(null);

        final CertificateProfile certificateProfile_dummy = new CertificateProfile();
        certificateProfile_dummy.setName("TestCP");

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);
        Mockito.when(commonProfileHelper.extractCertificateExtensions(certificateProfile)).thenThrow(new CertificateExtensionException());
        epSubjectAltNameValidator.validate(entityProfile);

    }

    /**
     * Method to test Invalid SujectAltNameFields present in EntityProfile.
     *
     * @throws Exception
     */
    @Test
    public void testValidateCreate_InvalidSubjectAltNameFieldType() throws Exception {

        when(commonProfileHelper.getCertificateProfile(certificateProfileName)).thenReturn(certificateProfile);

        epSubjectAltNameValidator.validate(entityProfile);

        Mockito.verify(commonProfileHelper).getCertificateProfile(certificateProfileName);

    }

    /**
     * Method to test Null SubjectAltNameExtension in entityProfile.
     */
    @Test
    public void testSubjectAltNameExtensionASNull() {

        entityProfile.setSubjectAltNameExtension(null);
        Assert.assertEquals(epSubjectAltNameValidator.validate(entityProfile), Boolean.FALSE);

    }

    /**
     * Method to test Invalid SubjectAltNameExtension Value.
     *
     * @throws Exception
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testInvalidSubjectAltNameExtension() throws Exception {
        final SubjectAltName entityProfileSubjectAltName = new SubjectAltName();
        entityProfileSubjectAltName.setCritical(true);
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("Test");
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameFields.add(subjectAltNameField);
        entityProfileSubjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        entityProfile.setSubjectAltNameExtension(entityProfileSubjectAltName);
        final List<CertificateExtension> certificateExtensions = entityProfile.getCertificateProfile().getCertificateExtensions().getCertificateExtensions();
        for (final CertificateExtension certificateExtension : certificateExtensions) {
            if (certificateExtension instanceof SubjectAltName) {
                final SubjectAltName subjectAltName = (SubjectAltName) certificateExtension;
                subjectAltName.setSubjectAltNameFields(null);
            }
        }
        epSubjectAltNameValidator.validate(entityProfile);

    }
}
