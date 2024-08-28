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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data;

import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * Class for DummyDataCreation
 * 
 */
public class CertificateProfileSetUpData {
    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;

    /**
     * Method to provide dummy data for tests.
     * 
     * @throws DatatypeConfigurationException
     */
    public CertificateProfileSetUpData() throws DatatypeConfigurationException {
        fillCertificateProfileData();
        fillCertificateProfile();
    }

    /**
     * Method to provide dummy CertificateProfileData object for Unit test
     * 
     * @return certificateProfileData
     */
    public CertificateProfileData getCertificateProfileData() {
        return certificateProfileData;
    }

    /**
     * Method to fill dummy data in CertificateProfileData object for Unit test
     */
    private void fillCertificateProfileData() {
        certificateProfileData = new CertificateProfileData();
        certificateProfileData.setActive(true);
        certificateProfileData.setForCAEntity(true);
        certificateProfileData.setVersion(CertificateVersion.V3);
        certificateProfileData.setId(123);
        certificateProfileData.setIssuerUniqueIdentifier(false);
        certificateProfileData.setName("TestCP");
        certificateProfileData.setSkewCertificateTime("PT30M");
        certificateProfileData.setSubjectUniqueIdentifier(true);
        certificateProfileData.setValidity("P340D");
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(getCertificateExtensions()));
        certificateProfileData.setSignatureAlgorithm(getAlgorithmData(AlgorithmType.SIGNATURE_ALGORITHM));
        final Set<AlgorithmData> keyGenerationAlgorithms = new HashSet<AlgorithmData>();
        keyGenerationAlgorithms.add(getAlgorithmData(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM));
        certificateProfileData.setKeyGenerationAlgorithms(keyGenerationAlgorithms);
        certificateProfileData.setIssuerData(getCAEntityData());
    }

    /**
     * Method that returns {@link CertificateProfileData} for CA entity
     * 
     * @param name
     *            name of certificate profile
     * @param entityProfileDatas
     * @return CertificateProfile
     * @throws DatatypeConfigurationException
     *             thrown when any errors occur handling Duration objects
     */
    public CertificateProfileData getCertificateProfileData(final long id, final String name, final CAEntityData issuerData, final Set<EntityProfileData> entityProfileDatas)
            throws DatatypeConfigurationException {
        final AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();

        final CertificateProfileData certificateProfileData = new CertificateProfileData();
        certificateProfileData.setId(id);
        certificateProfileData.setVersion(CertificateVersion.V3);
        certificateProfileData.setActive(true);
        certificateProfileData.setForCAEntity(true);
        certificateProfileData.setIssuerUniqueIdentifier(false);
        certificateProfileData.setIssuerData(issuerData);
        certificateProfileData.setName(name);
        certificateProfileData.setSkewCertificateTime("PT30M");
        certificateProfileData.setValidity("P340D");
        certificateProfileData.setSubjectUniqueIdentifier(true);
        certificateProfileData.setSignatureAlgorithm(algorithmDataSetUp.getSupportedSignatureAlgorithm());
        certificateProfileData.setKeyGenerationAlgorithms(algorithmDataSetUp.getKeyGenerationAlgorithmList());
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(getCertificateExtensions()));

        return certificateProfileData;
    }

    /**
     * Method to provide dummy CertificateProfile object for unit test.
     * 
     * @return certificateProfile
     */
    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }

    /**
     * Method to fill dummy data in CertificateProfile object for Unit test
     */
    private void fillCertificateProfile() throws DatatypeConfigurationException {
        CAEntity caEntity = new CAEntity();
        certificateProfile = new CertificateProfile();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        caEntity = entitiesSetUpData.getCaEntityList().get(0);
        certificateProfile.setActive(true);
        certificateProfile.setForCAEntity(true);
        certificateProfile.setId(123);
        certificateProfile.setIssuer(caEntity);
        certificateProfile.setIssuerUniqueIdentifier(false);
        certificateProfile.setName("TestCP");
        certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration("PT1H1M30S"));
        certificateProfile.setSubjectUniqueIdentifier(true);
        certificateProfile.setCertificateValidity(DatatypeFactory.newInstance().newDuration("P360D"));
        certificateProfile.setVersion(CertificateVersion.V3);
        certificateProfile.setCertificateExtensions(getCertificateExtensions());
        certificateProfile.setSignatureAlgorithm(getAlgorithm(AlgorithmType.SIGNATURE_ALGORITHM));
        certificateProfile.setSubjectCapabilities(getSubject());
        certificateProfile.setIssuerUniqueIdentifier(false);
        final List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();
        keygenerationAlgorithms.add(getAlgorithm(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM));
        certificateProfile.setKeyGenerationAlgorithms(keygenerationAlgorithms);
    }

    /**
     * Method to provide dummy CAEntityData object for unit test.
     * 
     * @return caEntityData
     */
    private CAEntityData getCAEntityData() {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("TestIssuer");
        certificateAuthorityData.setRootCA(true);

        final CAEntityData caEntityData = new CAEntityData();
        caEntityData.setId(111);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        return caEntityData;
    }

    /**
     * Method to provide dummy CertificateExtensions object for unit test.
     * 
     * @return CertificateExtensions
     */
    private CertificateExtensions getCertificateExtensions() {
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        certificateExtensionList.add(getAuthorityInformationAccess());
        certificateExtensionList.add(getAuthorityKeyIdentifier());
        certificateExtensionList.add(getExtendedKeyUsage());
        certificateExtensionList.add(getKeyUsage());
        certificateExtensionList.add(getSubjectAltName());
        certificateExtensionList.add(getSubjectKeyIdentifier());
        certificateExtensionList.add(getBasicConstraints());
        certificateExtensionList.add(getCRLDistributionPoints());

        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        return certificateExtensions;
    }

    /**
     * Method to provide dummy AlgorithmData object for unit test.
     * 
     * @return algorithmData
     * @param algorithmType
     *            this can be signature algorithm or key generation algorithm
     */
    private AlgorithmData getAlgorithmData(final AlgorithmType algorithmType) {
        final Set<Integer> categories = new HashSet<Integer>();

        categories.add(AlgorithmCategory.OTHER.getId());

        final AlgorithmData algorithmData = new AlgorithmData();
        if (algorithmType.getId() == AlgorithmType.SIGNATURE_ALGORITHM.getId()) {
            algorithmData.setType(AlgorithmType.SIGNATURE_ALGORITHM.getId());
            algorithmData.setId(102);
            algorithmData.setName("TestSA");
            algorithmData.setCategories(categories);
        } else if (algorithmType.getId() == AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId()) {
            algorithmData.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId());
            algorithmData.setId(101);
            algorithmData.setName("TestKGA");
            algorithmData.setCategories(categories);
        }
        algorithmData.setKeySize(2048);
        algorithmData.setOid("0.1.2");
        algorithmData.setSupported(true);
        return algorithmData;
    }

    /**
     * Method to provide dummy Algorithm object for unit test.
     * 
     * @return algorithm
     * @param algorithmType
     *            this can be signature algorithm or key generation algorithm
     */
    private Algorithm getAlgorithm(final AlgorithmType algorithmType) {
        final List<AlgorithmCategory> categories = new ArrayList<AlgorithmCategory>();
        categories.add(AlgorithmCategory.OTHER);
        final Algorithm algorithm = new Algorithm();
        if (algorithmType.getId() == AlgorithmType.SIGNATURE_ALGORITHM.getId()) {
            algorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
            algorithm.setName("TestSA");
        } else if (algorithmType.getId() == AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId()) {
            algorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
            algorithm.setName("TestKGA");
        }
        algorithm.setKeySize(2048);
        algorithm.setOid("0.1.2");
        algorithm.setSupported(true);
        algorithm.setCategories(categories);
        return algorithm;
    }

    /**
     * Method to provide dummy SubjectKeyIdentifier object for unit test.
     * 
     * @return subjectKeyIdentifier
     */
    public SubjectKeyIdentifier getSubjectKeyIdentifier() {
        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setAlgorithm(getAlgorithm(AlgorithmType.SIGNATURE_ALGORITHM));
        subjectKeyIdentifier.setCritical(false);
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        return subjectKeyIdentifier;
    }

    /**
     * Method to provide dummy AuthorityKeyIdentifier object for unit test.
     * 
     * @return authorityKeyIdentifier
     */
    private AuthorityKeyIdentifier getAuthorityKeyIdentifier() {
        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setType(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER);

        authorityKeyIdentifier.setCritical(false);
        authorityKeyIdentifier.setType(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER);
        return authorityKeyIdentifier;
    }

    /**
     * Method to provide dummy BasicConstraints object for unit test.
     * 
     * @return basicConstraints
     */
    private BasicConstraints getBasicConstraints() {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setIsCA(true);
        basicConstraints.setCritical(true);
        basicConstraints.setPathLenConstraint(0);
        return basicConstraints;
    }

    /**
     * Method to provide dummy AuthorityInformationAccess object for unit test.
     * 
     * @return authorityInformationAccess
     */
    private AuthorityInformationAccess getAuthorityInformationAccess() {
        final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        authorityInformationAccess.setAccessDescriptions(null);
        authorityInformationAccess.setCritical(false);
        return authorityInformationAccess;
    }

    /**
     * Method to provide dummy SubjectAltName object for unit test.
     * 
     * @return subjectAltName
     */
    private SubjectAltName getSubjectAltName() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setType(SubjectAltNameFieldType.DNS_NAME);
        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameField.setType(SubjectAltNameFieldType.REGESTERED_ID);
        subjectAltNameField.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);

        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    /**
     * Method to provide dummy KeyUsage object for unit test.
     * 
     * @return keyUsage
     */
    public KeyUsage getKeyUsage() {
        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        return keyUsage;
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
     * Method to provide dummy CRLDistributionPoint object for unit test.
     * 
     * @return crlDistributionPoint
     */
    private DistributionPoint getCrlDistributionPoint() {
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> strNames = new ArrayList<String>();
        strNames.add("http://$FQDN_IPV4/pki-cdps?ca_name=$CANAME&ca_cert_serialnumber=$CACERTSERIALNUMBER");
        distributionPointName.setFullName(strNames);
        final DistributionPoint crlDistributionPoint = new DistributionPoint();
        crlDistributionPoint.setDistributionPointName(distributionPointName);
        crlDistributionPoint.setReasonFlag(ReasonFlag.CERTIFICATE_HOLD);
        return crlDistributionPoint;
    }

    /**
     * Method to provide dummy CRLDistributionPoints object for unit test.
     * 
     * @return crlDistributionPoints
     */
    private CRLDistributionPoints getCRLDistributionPoints() {
        final List<DistributionPoint> crlDistributionPointList = new ArrayList<DistributionPoint>();
        crlDistributionPointList.add(getCrlDistributionPoint());

        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        crlDistributionPoints.setCritical(false);
        crlDistributionPoints.setDistributionPoints(crlDistributionPointList);
        return crlDistributionPoints;
    }

    /**
     * Method to provide dummy Subject for tests.
     */

    public Subject getSubject() {

        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(getSubjectField(SubjectFieldType.COMMON_NAME));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION));
        subjectFields.add(getSubjectField(SubjectFieldType.ORGANIZATION_UNIT));
        subjectFields.add(getSubjectField(SubjectFieldType.SERIAL_NUMBER));
        subjectFields.add(getSubjectField(SubjectFieldType.TITLE));
        subjectFields.add(getSubjectField(SubjectFieldType.COUNTRY_NAME));
        subjectFields.add(getSubjectField(SubjectFieldType.STATE));
        subjectFields.add(getSubjectField(SubjectFieldType.GIVEN_NAME));
        subjectFields.add(getSubjectField(SubjectFieldType.SURNAME));
        subjectFields.add(getSubjectField(SubjectFieldType.DC));
        subjectFields.add(getSubjectField(SubjectFieldType.INITIALS));
        subjectFields.add(getSubjectField(SubjectFieldType.GENERATION));
        subjectFields.add(getSubjectField(SubjectFieldType.EMAIL_ADDRESS));

        subject.setSubjectFields(subjectFields);
        return subject;
    }

    /**
     * Method to provide dummy SubjectField for tests.
     */

    private SubjectField getSubjectField(final SubjectFieldType subjectFieldType) {
        final SubjectField subjectField = new SubjectField();
        subjectField.setType(subjectFieldType);

        return subjectField;
    }

    /**
     * Method to provide dummy CertificateExtensions object for unit test.
     * 
     * @return CertificateExtensions
     */
    public CertificateExtensions getCertificateExtensions_WithInvalidSubjectAltName() {
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        certificateExtensionList.add(getAuthorityInformationAccess());
        certificateExtensionList.add(getAuthorityKeyIdentifier());
        certificateExtensionList.add(getExtendedKeyUsage());
        certificateExtensionList.add(getKeyUsage());
        certificateExtensionList.add(getSubjectAltName_EmptySubjectFields());
        certificateExtensionList.add(getSubjectKeyIdentifier());
        certificateExtensionList.add(getBasicConstraints());
        certificateExtensionList.add(getCRLDistributionPoints());

        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        return certificateExtensions;
    }

    /**
     * Method to provide dummy SubjectAltName object for unit test.
     * 
     * @return subjectAltName
     */
    private SubjectAltName getSubjectAltName_EmptySubjectFields() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();

        subjectAltNameFields.add(subjectAltNameField);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    /**
     * Method to return List of certificate extensions
     */
    public List<CertificateExtension> getCertificateExtensions(final CertificateProfile certificateProfile) {
        return certificateProfile.getCertificateExtensions().getCertificateExtensions();

    }

    public List<KeyUsageType> getKeyUsageTypeList() {
        final KeyUsage keyUsageExtension = (KeyUsage) certificateProfile.getCertificateExtensions().getCertificateExtensions().get(0);
        return keyUsageExtension.getSupportedKeyUsageTypes();
    }

}
