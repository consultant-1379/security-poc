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
package com.ericsson.oss.itpf.security.pki.manager.persistence.common.data;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;

public class EntitiesSetUpData {

    public final static String SUBJECT_STRING = "CN=ENM_Root";

    public final static String SUBJECT_ALT_NAME_JSON = "{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"www.xyz.com\"}}]}";
    public final static String CA_NAME_PATH = "certificateAuthorityData.name";
    public final static String ENTITY_NAME_PATH = "entityInfoData.name";
    public static final String ALGORITHM_KEY_SIZE = "keySize";
    public static final String ALGORITHM_TYPE = "type";
    public static final String NAME = "name";
    public static final int FAILURE = 1;
    public static final int SUCCESS = 0;

    Entity entity;
    EntityData entityData;
    List<EntityData> entityDataList = new ArrayList<EntityData>();
    List<Entity> entityList = new ArrayList<Entity>();

    CAEntity caEntity;
    CAEntityData caEntityData;

    ExtCA extCA;
    CAEntityData extCAData;

    List<CAEntityData> caEntityDataList = new ArrayList<CAEntityData>();
    List<CAEntity> caEntityList = new ArrayList<CAEntity>();

    EntityProfileData entityProfileData;
    CertificateProfileData certificateProfileData;
    Set<CertificateProfileData> certificateProfileDatas;

    Map<String, Object> entityInput = new HashMap<String, Object>();

    final private EntityCategorySetUpData entityCategorySetUpData;

    public <T extends AbstractSubjectAltNameFieldValue> EntitiesSetUpData() {

        entityCategorySetUpData = new EntityCategorySetUpData();

        entityProfileData = createEntityProfileData();

        certificateProfileData = createCertificateProfileData();

        certificateProfileDatas = createCertProfileDataSet();

        entity = createEntity();
        entityData = createEntityData();

        entityList.add(entity);
        entityDataList.add(entityData);

        caEntity = createCAEntity();
        caEntityData = createCAEntityData();

        extCA = createExtCA();
        extCAData = createExtCAData();

        caEntityList.add(caEntity);
        caEntityDataList.add(caEntityData);

        entityInput.put("id", 1);
        entityInput.put("name", "TestEntity");

    }

    private EntityData createEntityData() {

        final EntityData entityData = new EntityData();
        final EntityInfoData entityInfoData = new EntityInfoData();

        entityInfoData.setName("ENMService");
        entityInfoData.setSubjectDN(SUBJECT_STRING);
        entityInfoData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        entityInfoData.setStatus(EntityStatus.NEW);
        entityInfoData.setOtp("2ER13SA32SAD2G3");
        entityInfoData.setOtpCount(9);
        entityInfoData.setIssuer(createCAEntityData());
        entityData.setEntityCategoryData(entityCategorySetUpData.getEntityCategoryData());
        entityData.setId(1);
        entityData.setEntityInfoData(entityInfoData);
        entityData.setEntityProfileData(createEntityProfileData());
        entityData.setKeyGenerationAlgorithm(createKeyGenerationAlgorithmData(1, "RSA", 1024));

        return entityData;
    }

    private CAEntityData createCAEntityData() {

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

    private CAEntity createCAEntity() {

        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setId(1);
        certificateAuthority.setName("TestIssuer");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setSubject(createSubject());
        certificateAuthority.setSubjectAltName(createSAN());

        caEntity.setCertificateAuthority(certificateAuthority);
        caEntity.setEntityProfile(createEntityProfile());
        caEntity.setKeyGenerationAlgorithm(createKeyGenerationAlgorithm(1, "RSA", 1024));

        return caEntity;

    }

    private CAEntityData createExtCAData() {

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

    private ExtCA createExtCA() {

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

    private Entity createEntity() {

        final Entity entity = new Entity();
        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setId(1);
        entityInfo.setName("ENMService");
        entityInfo.setSubject(createSubject());
        entityInfo.setSubjectAltName(createSAN());
        entityInfo.setIssuer(createCAEntity().getCertificateAuthority());
        entity.setCategory(entityCategorySetUpData.getEntityCategory());
        entity.setEntityInfo(entityInfo);
        entity.setEntityProfile(createEntityProfile());
        entity.setKeyGenerationAlgorithm(createKeyGenerationAlgorithm(1, "RSA", 1024));

        return entity;

    }

    private Subject createSubject() {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue("ENM_Root");
        subjectFields.add(subjectField);

        subject.setSubjectFields(subjectFields);

        return subject;
    }

    private <T> SubjectAltName createSAN() {

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

    private EntityProfileData createEntityProfileData() {

        final EntityProfileData entityProfileData = new EntityProfileData();

        entityProfileData.setId(1);
        entityProfileData.setName("ENMRootCAEntityProfile");
        entityProfileData.setSubjectDN("CN=ENM_Root");
        entityProfileData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        entityProfileData.setKeyGenerationAlgorithm(createKeyGenerationAlgorithmData(1, "RSA", 1024));
        entityProfileData.setCertificateProfileData(createCertificateProfileData());

        return entityProfileData;

    }

    private EntityProfile createEntityProfile() {

        final EntityProfile entityProfile = new EntityProfile();

        entityProfile.setId(1);
        entityProfile.setName("ENMRootCAEntityProfile");

        return entityProfile;

    }

    private CertificateProfileData createCertificateProfileData() {

        final CertificateProfileData certificateProfileData = new CertificateProfileData();

        certificateProfileData.setId(1);
        certificateProfileData.setName("ENMRootCACertificateProfile");
        certificateProfileData.setForCAEntity(true);
        certificateProfileData.setKeyGenerationAlgorithms(createKeyGenerationAlgorithmDataSet());

        return certificateProfileData;

    }

    private Set<CertificateProfileData> createCertProfileDataSet() {

        final Set<CertificateProfileData> certificateProfileDatas = new HashSet<CertificateProfileData>();

        certificateProfileDatas.add(createCertificateProfileData());

        return certificateProfileDatas;

    }

    private Algorithm createKeyGenerationAlgorithm(final int id, final String name, final Integer keySize) {

        final Algorithm keyGenAlgorithm = new Algorithm();

        keyGenAlgorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        keyGenAlgorithm.setId(id);
        keyGenAlgorithm.setName(name);
        keyGenAlgorithm.setKeySize(keySize);

        return keyGenAlgorithm;

    }

    private AlgorithmData createKeyGenerationAlgorithmData(final int id, final String name, final Integer keySize) {

        final AlgorithmData keyGenAlgorithmData = new AlgorithmData();

        keyGenAlgorithmData.setId(id);
        keyGenAlgorithmData.setKeySize(keySize);
        keyGenAlgorithmData.setName(name);
        keyGenAlgorithmData.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId());
        keyGenAlgorithmData.setSupported(true);

        return keyGenAlgorithmData;

    }

    private Set<AlgorithmData> createKeyGenerationAlgorithmDataSet() {

        final Set<AlgorithmData> keyAlgorithmDataSet = new HashSet<AlgorithmData>();

        final AlgorithmData keyGenerationAlgorithmData = createKeyGenerationAlgorithmData(1, "RSA", 1024);
        final AlgorithmData keyGenerationAlgorithmData1 = createKeyGenerationAlgorithmData(2, "AES", 256);

        keyAlgorithmDataSet.add(keyGenerationAlgorithmData);
        keyAlgorithmDataSet.add(keyGenerationAlgorithmData1);

        return keyAlgorithmDataSet;

    }

    /**
     * @return the entity
     */
    public Entity getEntity() {
        return entity;
    }

    /**
     * @return the entityData
     */
    public EntityData getEntityData() {
        return entityData;
    }

    /**
     * @return the caEntity
     */
    public CAEntity getCaEntity() {
        return caEntity;
    }

    /**
     * @return the caEntityData
     */
    public CAEntityData getCaEntityData() {
        return caEntityData;
    }

    /**
     * @return the extCA
     */
    public ExtCA getExtCA() {
        return extCA;
    }

    /**
     * @param extCA
     *            the extCA to set
     */
    public void setExtCA(final ExtCA extCA) {
        this.extCA = extCA;
    }

    /**
     * @return the extCAData
     */
    public CAEntityData getExtCAData() {
        return extCAData;
    }

    /**
     * @param extCAData
     *            the extCAData to set
     */
    public void setExtCAData(final CAEntityData extCAData) {
        this.extCAData = extCAData;
    }

    /**
     * @return the entityProfileData
     */
    public EntityProfileData getEntityProfileData() {
        return entityProfileData;
    }

    /**
     * @return the certificateProfileData
     */
    public CertificateProfileData getCertificateProfileData() {
        return certificateProfileData;
    }

    /**
     * @return the entityDataList
     */
    public List<EntityData> getEntityDataList() {
        return entityDataList;
    }

    /**
     * @return the caEntityDataList
     */
    public List<CAEntityData> getCaEntityDataList() {
        return caEntityDataList;
    }

    /**
     * @return the entityList
     */
    public List<Entity> getEntityList() {
        return entityList;
    }

    /**
     * @return the caEntityList
     */
    public List<CAEntity> getCaEntityList() {
        return caEntityList;
    }

    /**
     * @return the certificateProfileDatas
     */
    public Set<CertificateProfileData> getCertificateProfileDatas() {
        return certificateProfileDatas;
    }

    /**
     * @return the input
     */
    public Map<String, Object> getInput() {
        return entityInput;
    }
}
