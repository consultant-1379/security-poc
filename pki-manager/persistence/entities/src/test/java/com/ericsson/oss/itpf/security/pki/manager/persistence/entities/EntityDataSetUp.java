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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public class EntityDataSetUp {
    public final static String SUBJECT_STRING = "CN=ENM_Root";

    public final static String SUBJECT_ALT_NAME_JSON = "{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"www.xyz.com\"}}]}";

    public EntityData createEntityData() {

        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();
        entityInfoData.setName("ENMService");
        entityInfoData.setSubjectDN(SUBJECT_STRING);
        entityInfoData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        entityInfoData.setStatus(EntityStatus.NEW);
        entityInfoData.setOtp("2ER13SA32SAD2G3");
        entityInfoData.setOtpCount(9);
        entityInfoData.setIssuer(createCAEntityData());
        entityData.setEntityCategoryData(getEntityCategoryData());
        entityData.setId(1);
        entityData.setEntityInfoData(entityInfoData);
        entityData.setEntityProfileData(createEntityProfileData());
        entityData.setKeyGenerationAlgorithm(createKeyGenerationAlgorithmData(1, "RSA", 1024));
        entityData.setCertificateExpiryNotificationDetailsData(getCertificateExpiryNotificationDetailsData());
        return entityData;
    }

    public Set<CertificateExpiryNotificationDetailsData> getCertificateExpiryNotificationDetailsData() {
        final Set<CertificateExpiryNotificationDetailsData> certExpiryNotificationDetailsDataset = new HashSet<CertificateExpiryNotificationDetailsData>();
        final CertificateExpiryNotificationDetailsData certExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
        certExpiryNotificationDetailsData.setNotificationSeverity(NotificationSeverity.MINOR.getId());
        certExpiryNotificationDetailsData.setPeriodBeforeExpiry(180);
        certExpiryNotificationDetailsData.setFrequencyOfNotification(7);
        certExpiryNotificationDetailsDataset.add(certExpiryNotificationDetailsData);
        return certExpiryNotificationDetailsDataset;

    }

    public CAEntityData createCAEntityData() {
        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("ENMRootCA");
        certificateAuthorityData.setSubjectDN(SUBJECT_STRING);
        certificateAuthorityData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        certificateAuthorityData.setIssuer(null);
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setStatus(CAStatus.NEW.getId());
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setId(1);
        caEntityData.setEntityProfileData(createEntityProfileData());
        caEntityData.setKeyGenerationAlgorithm(createKeyGenerationAlgorithmData(1, "RSA", 1024));
        caEntityData.setExternalCA(false);
        return caEntityData;

    }

    public CAEntity createCAEntity() {

        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(1);
        certificateAuthority.setName("ENMRootCA");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setSubject(createSubject());
        certificateAuthority.setSubjectAltName(createSAN());
        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setEntityProfile(createEntityProfile());
        caEntity.setKeyGenerationAlgorithm(createKeyGenerationAlgorithm(1, "RSA", 1024));
        return caEntity;

    }

    public CAEntityData createExtCAData() {

        final CAEntityData extCAData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("ENMRootCA");
        certificateAuthorityData.setSubjectDN(SUBJECT_STRING);
        certificateAuthorityData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        certificateAuthorityData.setIssuer(null);
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setStatus(CAStatus.NEW.getId());
        extCAData.setCertificateAuthorityData(certificateAuthorityData);
        extCAData.setId(1);
        extCAData.setEntityProfileData(createEntityProfileData());
        extCAData.setKeyGenerationAlgorithm(createKeyGenerationAlgorithmData(1, "RSA", 1024));
        extCAData.setExternalCA(true);
        return extCAData;

    }

    public ExtCA createExtCA() {

        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(2);
        certificateAuthority.setName("ENMRootCA");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setSubject(createSubject());
        certificateAuthority.setSubjectAltName(createSAN());
        extCA.setCertificateAuthority(certificateAuthority);
        final List<ExtCA> associated = new ArrayList<ExtCA>();
        final ExtCA extCAEl = new ExtCA();
        extCAEl.setCertificateAuthority(certificateAuthority);
        extCAEl.setAssociated(new ArrayList<ExtCA>());
        associated.add(extCAEl);

        extCA.setAssociated(associated);
        return extCA;

    }

    public Entity createEntity() {
        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setId(1);
        entityInfo.setName("ENMService");
        entityInfo.setSubject(createSubject());
        entityInfo.setSubjectAltName(createSAN());
        entityInfo.setIssuer(createCAEntity().getCertificateAuthority());
        entity.setCategory(getEntityCategory());
        entity.setEntityInfo(entityInfo);
        entity.setEntityProfile(createEntityProfile());
        entity.setKeyGenerationAlgorithm(createKeyGenerationAlgorithm(1, "RSA", 1024));
        return entity;

    }

    public EntityCategoryData getEntityCategoryData() {
        EntityCategoryData entityCategoryData = new EntityCategoryData();
        entityCategoryData.setId(1);
        entityCategoryData.setModifiable(true);
        entityCategoryData.setName("EndEntity");
        return entityCategoryData;
    }

    public EntityCategory getEntityCategory() {
        EntityCategory entityCategoryData = new EntityCategory();
        entityCategoryData.setId(1);
        entityCategoryData.setModifiable(true);
        entityCategoryData.setName("EndEntity");
        return entityCategoryData;
    }

    public Subject createSubject() {
        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue("ENM_Root");
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        return subject;
    }

    public <T> SubjectAltName createSAN() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("www.xyz.com");
        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);
        return subjectAltName;

    }

    public EntityProfileData createEntityProfileData() {

        final EntityProfileData entityProfileData = new EntityProfileData();
        entityProfileData.setId(1);
        entityProfileData.setName("ENMRootCAEntityProfile");
        entityProfileData.setSubjectDN("CN=ENM_Root");
        entityProfileData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        entityProfileData.setKeyGenerationAlgorithm(createKeyGenerationAlgorithmData(1, "RSA", 1024));
        entityProfileData.setCertificateProfileData(createCertificateProfileData());
        return entityProfileData;

    }

    public EntityProfile createEntityProfile() {
        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setId(1);
        entityProfile.setName("ENMRootCAEntityProfile");
        return entityProfile;

    }

    public CertificateProfileData createCertificateProfileData() {
        final CertificateProfileData certificateProfileData = new CertificateProfileData();
        certificateProfileData.setId(1);
        certificateProfileData.setName("ENMRootCACertificateProfile");
        certificateProfileData.setForCAEntity(true);
        certificateProfileData.setKeyGenerationAlgorithms(createKeyGenerationAlgorithmDataSet());
        return certificateProfileData;

    }

    public Set<CertificateProfileData> createCertProfileDataSet() {
        final Set<CertificateProfileData> certificateProfileDatas = new HashSet<CertificateProfileData>();
        certificateProfileDatas.add(createCertificateProfileData());
        return certificateProfileDatas;
    }

    public Algorithm createKeyGenerationAlgorithm(final int id, final String name, final Integer keySize) {

        final Algorithm keyGenAlgorithm = new Algorithm();
        keyGenAlgorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        keyGenAlgorithm.setId(id);
        keyGenAlgorithm.setName(name);
        keyGenAlgorithm.setKeySize(keySize);
        return keyGenAlgorithm;

    }

    public AlgorithmData createKeyGenerationAlgorithmData(final int id, final String name, final Integer keySize) {
        final AlgorithmData keyGenAlgorithmData = new AlgorithmData();
        keyGenAlgorithmData.setId(id);
        keyGenAlgorithmData.setKeySize(keySize);
        keyGenAlgorithmData.setName(name);
        keyGenAlgorithmData.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId());
        keyGenAlgorithmData.setSupported(true);
        return keyGenAlgorithmData;

    }

    public Set<AlgorithmData> createKeyGenerationAlgorithmDataSet() {
        final Set<AlgorithmData> keyAlgorithmDataSet = new HashSet<AlgorithmData>();
        final AlgorithmData keyGenerationAlgorithmData = createKeyGenerationAlgorithmData(1, "RSA", 1024);
        final AlgorithmData keyGenerationAlgorithmData1 = createKeyGenerationAlgorithmData(2, "AES", 256);
        keyAlgorithmDataSet.add(keyGenerationAlgorithmData);
        keyAlgorithmDataSet.add(keyGenerationAlgorithmData1);
        return keyAlgorithmDataSet;

    }
}
