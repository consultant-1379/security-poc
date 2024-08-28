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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data;

import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * Class for DummyDataCreation
 * 
 */
public class EntityProfileSetUpData {
    public final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";
    public final static String NAME_PATH = "name";
    public static final int FAILURE = 1;
    public static final int SUCCESS = 0;
    private static final int ID = 1;
    private static final String NAME = "EndEntity";

    private static final EntityProfile entityProfile = new EntityProfile();
    private static final EntityProfileData entityProfileData = new EntityProfileData();
    private CertificateProfile certificateProfile = new CertificateProfile();
    private CertificateProfileData certificateProfileData = new CertificateProfileData();
    private static CertificateProfileSetUpData certificateProfileSetUpData;
    private static TrustProfileSetUpData trustProfileSetUpData;
    private static EntityCategorySetUpData entityCategorySetUpData;

    /**
     * Method to provide dummy data for tests.
     */

    public EntityProfileSetUpData() throws DatatypeConfigurationException {
        entityCategorySetUpData = new EntityCategorySetUpData();
        certificateProfileSetUpData = new CertificateProfileSetUpData();
        trustProfileSetUpData = new TrustProfileSetUpData();
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        setEntityProfileData(entityProfileData, certificateProfileSetUpToTest);
        setEntityProfile(entityProfile);
    }

    /**
     * Method to provide dummy entityProfile for tests.
     */
    public EntityProfile getEntityProfile() {
        return entityProfile;
    }

    private Subject getSubject() {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME, "CHandra"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION, "tcs"));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT, "Ericsson"));
        subjectFields.add(getSubjectField(SubjectFieldType.SERIAL_NUMBER, "1234"));
        subjectFields.add(getSubjectField(SubjectFieldType.TITLE, "Certificate"));
        subjectFields.add(getSubjectField(SubjectFieldType.COUNTRY_NAME, "IN"));
        subjectFields.add(getSubjectField(SubjectFieldType.STATE, "AndhraPradesh"));
        subjectFields.add(getSubjectField(SubjectFieldType.GIVEN_NAME, "RootCA"));
        subjectFields.add(getSubjectField(SubjectFieldType.SURNAME, "google"));

        subject.setSubjectFields(subjectFields);
        return subject;
    }

    private SubjectField getSubjectField(final SubjectFieldType subjectFieldType, final String subjectValue) {
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(subjectFieldType);
        subjectField.setValue(subjectValue);
        return subjectField;
    }

    private void setEntityProfile(final EntityProfile entityProfile) {
        final List<TrustProfile> tprofiles = new ArrayList<TrustProfile>();
        final Algorithm keyGenerationAlgorithm = new Algorithm();
        entityProfile.setName("EntityProfile_1");
        entityProfile.setId(101);
        entityProfile.setSubject(getSubject());
        entityProfile.setSubjectAltNameExtension(getSubjectAltName());
        entityProfile.setExtendedKeyUsageExtension(getExtendedKeyUsage());
        entityProfile.setCategory(getEntityCategory());
        entityProfile.setKeyUsageExtension(certificateProfileSetUpData.getKeyUsage());

        entityProfile.setCertificateProfile(certificateProfileSetUpData.getCertificateProfile());
        keyGenerationAlgorithm.setName("RSA");
        keyGenerationAlgorithm.setKeySize(2048);
        entityProfile.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        final TrustProfile trustProfile = trustProfileSetUpData.getTrustProfile();
        tprofiles.add(trustProfile);
        entityProfile.setTrustProfiles(tprofiles);
    }

    /**
     * Method to provide dummy entityProfileData for tests.
     */
    public EntityProfileData getEntityProfileData() {
        return entityProfileData;
    }

    /**
     * Method that returns {@link EntityProfileData} for CA entity
     * 
     * @param name
     *            name of entity profile
     * @param caEntityDatas
     *            Set of {@link CAEntityData} to be set in {@link EntityProfileData}
     * @param certificateProfileData
     *            {@link CertificateProfileData} to be set
     * @return {@link EntityProfileData} Instance of {@link EntityProfileData} with given values set.
     * @throws DatatypeConfigurationException
     *             thrown when any errors occur handling Duration objects
     */
    public EntityProfileData getEntityProfileForCA(final long id, final String name, final String subject, final CertificateProfileData certificateProfileData, final Set<CAEntityData> caEntityDatas)
            throws DatatypeConfigurationException {
        final AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();

        final EntityProfileData entityProfile = new EntityProfileData();
        entityProfile.setId(id);
        entityProfile.setActive(true);
        entityProfile.setName(name);
        entityProfile.setKeyGenerationAlgorithm(algorithmDataSetUp.getSupportedKeyGenerationAlgorithm());
        entityProfile.setSubjectDN(subject);
        entityProfile.setCertificateProfileData(certificateProfileData);

        return entityProfile;
    }

    /**
     * Method to provide dummy CertificateExtensions of ExtendedKeyUsage for tests.
     */
    public CertificateExtensions getExtendedKeyUsageCertificateExtensions() {
        final CertificateExtensions certExtensions = new CertificateExtensions();
        final List<CertificateExtension> certList = new ArrayList<CertificateExtension>();
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        certList.add(extendedKeyUsage);
        certExtensions.setCertificateExtensions(certList);
        return certExtensions;
    }

    private EntityCategory getEntityCategory() {
        final EntityCategory entityCategory = new EntityCategory();
        entityCategory.setId(ID);
        entityCategory.setModifiable(true);
        entityCategory.setName(NAME);
        return entityCategory;
    }

    /**
     * Method to provide dummy ExtendedKeyUsage object for unit test.
     * 
     * @return extendedKeyUsage
     */

    private ExtendedKeyUsage getExtendedKeyUsage() {
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(false);
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        return extendedKeyUsage;
    }

    /**
     * Method to provide dummy CertificateExtensions of KeyUsag for tests.
     */
    public CertificateExtensions getKeyUsageCertificateExtensions() {
        final CertificateExtensions certExtensions = new CertificateExtensions();
        final List<CertificateExtension> certList = new ArrayList<CertificateExtension>();
        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        certList.add(keyUsage);
        certExtensions.setCertificateExtensions(certList);
        return certExtensions;
    }

    /**
     * Method to provide dummy CertificateExtensions of Invalid KeyUsage for tests.
     */
    public CertificateExtensions getInvalidKeyUsageExtensions() {
        final CertificateExtensions certExtensions = new CertificateExtensions();
        final List<CertificateExtension> certList = new ArrayList<CertificateExtension>();
        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.KEY_ENCIPHERMENT);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        certList.add(keyUsage);
        certExtensions.setCertificateExtensions(certList);
        return certExtensions;
    }

    /**
     * Method to provide dummy CertificateExtensions of Invalid Extended KeyUsage for tests.
     */
    public CertificateExtensions getInvalidExtendedKeyUsageExtensions() {
        final CertificateExtensions certExtensions = new CertificateExtensions();
        final List<CertificateExtension> certList = new ArrayList<CertificateExtension>();
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ID_KP_TIME_STAMPING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        certList.add(extendedKeyUsage);
        certExtensions.setCertificateExtensions(certList);
        return certExtensions;
    }

    /**
     * Method to provide dummy AlgorithmData for tests.
     */
    public AlgorithmData getAlgorithmData() {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setKeySize(2048);
        algorithmData.setName("RSA");
        algorithmData.setSupported(true);
        return algorithmData;
    }

    /**
     * Method to provide dummy SubjectAltName object for unit test.
     * 
     * @return subjectAltName
     */

    public SubjectAltName getInvalidSubjectAltName() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        final List<SubjectAltNameFieldType> subjectAltNameFieldTypes = new ArrayList<SubjectAltNameFieldType>();
        subjectAltNameFieldTypes.add(SubjectAltNameFieldType.DIRECTORY_NAME);
        return subjectAltName;
    }

    /**
     * Method to provide dummy SubjectAltName object for unit test.
     * 
     * @return subjectAltName
     */

    public SubjectAltName getSubjectAltName() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        final List<SubjectAltNameFieldType> subjectAltNameFieldTypes = new ArrayList<SubjectAltNameFieldType>();
        subjectAltNameFieldTypes.add(SubjectAltNameFieldType.DIRECTORY_NAME);

        return subjectAltName;
    }

    private String getSubjectAltNameJSON() {
        final String sanJSON = "{\"subjectAltNameValue\":[{\"type\":\"DIRECTORY_NAME\",\"value\":[{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}]},"
                + "{\"type\":\"OTHER_NAME\",\"value\":[{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}]},"
                + "{\"type\":\"RFC822_NAME\",\"value\":[{\"@class\":\".SubjectAltNameString\",\"value\":\"test@ericsson.com\"}]},"
                + "{\"type\":\"IP_ADDRESS\",\"value\":[{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}]},"
                + "{\"type\":\"DNS_NAME\",\"value\":[{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}]},"
                + "{\"type\":\"REGESTERED_ID\",\"value\":[{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}]},"
                + "{\"type\":\"EDI_PARTY_NAME\",\"value\":[{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}]},"
                + "{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":[{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}]}" + "]}";
        return sanJSON;
    }

    private void setEntityProfileData(final EntityProfileData entityProfileData, final CertificateProfileSetUpData certificateProfileSetUpToTest) {
        final Set<TrustProfileData> tpDataSet = new HashSet<TrustProfileData>();
        final TrustProfileData tp = new TrustProfileData();
        entityProfileData.setName("EntityProfile_1");
        entityProfileData.setId(101);
        entityProfileData.setSubjectAltName(JsonUtil.getJsonFromObject(getSubjectAltName()));
        entityProfileData.setSubjectDN(certificateProfileSetUpData.getSubject().toASN1String());
        entityProfileData.setEntityCategory(entityCategorySetUpData.getEntityCategoryData());

        entityProfileData.setExtendedKeyUsageExtension(JsonUtil.getJsonFromObject(getExtendedKeyUsage()));
        entityProfileData.setKeyGenerationAlgorithm(getAlgorithmData());
        entityProfileData.setKeyUsageExtension(JsonUtil.getJsonFromObject(certificateProfileSetUpData.getKeyUsage()));
        entityProfileData.setCertificateProfileData(certificateProfileSetUpToTest.getCertificateProfileData());
        tp.setName("TrustProfile_1");
        tpDataSet.add(tp);
        entityProfileData.setTrustProfileDatas(tpDataSet);
    }

    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }

    public void setCertificateProfile(final CertificateProfile certificateProfile) {
        this.certificateProfile = certificateProfile;
    }

    public CertificateProfileData getCertificateProfileData() {
        return certificateProfileData;
    }

    public void setCertificateProfileData(final CertificateProfileData certificateProfileData) {
        this.certificateProfileData = certificateProfileData;
    }

}
