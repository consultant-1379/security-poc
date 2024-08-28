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
package com.ericsson.oss.itpf.security.pki.manager.resources.profilemanagement.setup;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.rest.setup.AlgorithmSetUpToTest;

public class EntityProfileSetUpToTest {

    EntityProfile entityProfile = new EntityProfile();

    /**
     * Method to provide dummy data for tests.
     */
    public EntityProfileSetUpToTest() {
        fillEntityProfile();
    }

    /**
     * Method that returns dummy entity profile
     * 
     * @return
     */
    public EntityProfile getEntityProfile() {
        return entityProfile;
    }

    /**
     * This method returns EntityProfile object for testing creation
     */
    private EntityProfile fillEntityProfile() {
        entityProfile.setName("TestProfile");
        entityProfile.setActive(true);
        entityProfile.setKeyGenerationAlgorithm(new AlgorithmSetUpToTest().getKeyGenerationAlgorithmList().get(0));
        entityProfile.setCertificateProfile(getCertificateProfile());
        entityProfile.setTrustProfiles(getTrustProfiles());
        entityProfile.setExtendedKeyUsageExtension(getExtendedKeyUsage());
        entityProfile.setKeyUsageExtension(getKeyUsage());
        entityProfile.setSubject(getSubject());
        entityProfile.setSubjectAltNameExtension(getSubjectAltName());
        entityProfile.setCategory(getEntityCategory());

        return entityProfile;
    }

    private KeyUsage getKeyUsage() {
        final KeyUsage keyUsage = new KeyUsage();
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();

        keyUsage.setCritical(true);
        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);

        return keyUsage;
    }

    private ExtendedKeyUsage getExtendedKeyUsage() {
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();

        extendedKeyUsage.setCritical(false);
        keyPurposeIds.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);

        return extendedKeyUsage;
    }

    private Subject getSubject() {
        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        final SubjectField s1 = new SubjectField();
        s1.setType(SubjectFieldType.COMMON_NAME);
        s1.setValue("test_common_name");
        subjectFields.add(s1);

        final SubjectField s2 = new SubjectField();
        s2.setType(SubjectFieldType.COUNTRY_NAME);
        s1.setValue("test_country_name");
        subjectFields.add(s2);

        subject.setSubjectFields(subjectFields);

        return subject;
    }

    private SubjectAltName getSubjectAltName() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setValue(getSubjectAltNameString("test_directory_name"));
        subjectAltNameFields.add(subjectAltNameField);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    private AbstractSubjectAltNameFieldValue getSubjectAltNameString(final String value) {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);

        return subjectAltNameString;
    }

    private EntityCategory getEntityCategory() {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setName("testEntityCategory");

        return entityCategory;
    }

    private CertificateProfile getCertificateProfile() {
        final CertificateProfile certificateProfile = new CertificateProfile();
        certificateProfile.setName("TestCertificateProfile");

        return certificateProfile;
    }

    private List<TrustProfile> getTrustProfiles() {
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();

        trustProfiles.add(new TrustProfileSetUpToTest().getTrustProfile());

        return trustProfiles;
    }
}
