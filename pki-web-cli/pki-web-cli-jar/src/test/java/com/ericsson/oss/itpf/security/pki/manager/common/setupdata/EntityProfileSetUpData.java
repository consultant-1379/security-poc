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
package com.ericsson.oss.itpf.security.pki.manager.common.setupdata;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class EntityProfileSetUpData {

    private static final String EQUAL_EP_NAME = "EqualEP";
    private static final String COMMON_NAME = "CNarquillian";
    private static final String DN_QUALIFIER = "DNarquillian";

    /**
     * Method that returns different valid EntityProfile
     * 
     * @return EntityProfile
     * @throws DatatypeConfigurationException
     * @throws Exception
     */
    public EntityProfile getEntityProfileForEqual() throws DatatypeConfigurationException {
        final EntityProfile entityProfile = new EntityProfile();
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();
        trustProfiles.add(new TrustProfileSetUpData().getTrustProfileDataForEqual());

        entityProfile.setActive(true);
        entityProfile.setKeyUsageExtension(new KeyUsageSetUpData().getKeyUsageForEqual());
        entityProfile.setExtendedKeyUsageExtension(new ExtendedKeyUsageSetUpData().getExtendedKeyUsageForEqual());
        entityProfile.setCertificateProfile(new CertificateProfileSetUpData().getCertificateProfileForEqual());
        entityProfile.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual());
        entityProfile.setName(EQUAL_EP_NAME);
        entityProfile.setSubject(getSubjectForEqual());
        entityProfile.setSubjectAltNameExtension(new SubjectAltNameStringSetUpData().getSANForCreate());
        entityProfile.setTrustProfiles(trustProfiles);
        entityProfile.setType(ProfileType.ENTITY_PROFILE);
        return entityProfile;
    }

    /**
     * Method that returns different valid EntityProfile
     * 
     * @return EntityProfile
     * @throws DatatypeConfigurationException
     * @throws Exception
     */
    public EntityProfile getEntityProfileForNotEqual() throws DatatypeConfigurationException {
        final EntityProfile entityProfile = new EntityProfile();
        final List<TrustProfile> trustProfiles = new ArrayList<TrustProfile>();
        trustProfiles.add(new TrustProfileSetUpData().getTrustProfileDataForEqual());

        entityProfile.setActive(false);
        entityProfile.setKeyUsageExtension(new KeyUsageSetUpData().getKeyUsageForNotEqual());
        entityProfile.setExtendedKeyUsageExtension(new ExtendedKeyUsageSetUpData().getExtendedKeyUsageForNotEqual());
        entityProfile.setCertificateProfile(new CertificateProfileSetUpData().getCertificateProfileForNotEqual());
        entityProfile.setKeyGenerationAlgorithm(new KeyGenerationAlgorithmSetUpData().getAlgorithmForNotEqual());
        entityProfile.setName(EQUAL_EP_NAME);
        entityProfile.setSubject(getSubjectForNotEqual());
        entityProfile.setSubjectAltNameExtension(new SubjectAltNameStringSetUpData().getSANForCreate());
        entityProfile.setTrustProfiles(trustProfiles);
        entityProfile.setType(ProfileType.ENTITY_PROFILE);
        return entityProfile;
    }

    private Subject getSubjectForEqual() {
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(COMMON_NAME);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        return subject;
    }

    private Subject getSubjectForNotEqual() {
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();

        subjectField.setType(SubjectFieldType.DN_QUALIFIER);
        subjectField.setValue(DN_QUALIFIER);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        return subject;
    }

    /**
     * Method that returns different valid EntityProfile
     * 
     * @return EntityProfile
     * @throws DatatypeConfigurationException
     * @throws Exception
     */
    public EntityProfile getEntityProfileForEntityEqual() throws DatatypeConfigurationException {
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(EQUAL_EP_NAME);
        return entityProfile;
    }

}
