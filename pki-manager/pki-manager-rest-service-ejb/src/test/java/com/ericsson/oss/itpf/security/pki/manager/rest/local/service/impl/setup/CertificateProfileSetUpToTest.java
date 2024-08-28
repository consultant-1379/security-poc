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
package com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl.setup;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.rest.local.service.impl.setup.AlgorithmSetUpToTest;

/**
 * Class for DummyDataCreation
 * 
 * @version 1.1.30
 */
public class CertificateProfileSetUpToTest {

    CertificateProfile certificateProfile = new CertificateProfile();
    CertificateExtensions certificateExtensions = new CertificateExtensions();

    /**
     * Method to provide dummy data for tests.
     */
    public CertificateProfileSetUpToTest() throws DatatypeConfigurationException {
        certificateProfile.setActive(true);
        certificateProfile.setForCAEntity(true);
        certificateProfile.setId(123);
        certificateProfile.setIssuer(getIssuer());
        certificateProfile.setIssuerUniqueIdentifier(false);
        certificateProfile.setName("TestCP");
        certificateProfile.setType(ProfileType.CERTIFICATE_PROFILE);
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration("PT1H1M30S"));
        certificateProfile.setSubjectUniqueIdentifier(true);
        certificateProfile.setCertificateValidity(DatatypeFactory.newInstance().newDuration("P360D"));
        certificateProfile.setVersion(CertificateVersion.V3);
        certificateProfile.setCertificateExtensions(createCertificateExtensions());
        certificateProfile.setKeyGenerationAlgorithms(new AlgorithmSetUpToTest().getKeyGenerationAlgorithmList());
        certificateProfile.setModifiable(true);
        certificateProfile.setSignatureAlgorithm(new AlgorithmSetUpToTest().getSignatureAlgorithm());
        certificateProfile.setSubjectCapabilities(createSubjectCapabilities());

    }

    /**
     * Method that builds Subject object with subject types supported by dummy certificate profile .
     */
    public Subject createSubjectCapabilities() {
        final Subject subject = new Subject();
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField s1 = new SubjectField();
        final SubjectField s2 = new SubjectField();
        s1.setType(SubjectFieldType.COMMON_NAME);
        s2.setType(SubjectFieldType.COUNTRY_NAME);
        subjectFields.add(s1);
        subjectFields.add(s2);
        subject.setSubjectFields(subjectFields);

        return subject;
    }

    private CAEntity getIssuer() {
        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("testCA");
        caEntity.setCertificateAuthority(certificateAuthority);
        return caEntity;
    }

    /**
     * Method to provide dummy supported SubjectFieldTypes for tests.
     */
    public List<SubjectFieldType> getSubjectFieldTypes() {

        final List<SubjectFieldType> subjectFieldTypes = new ArrayList<SubjectFieldType>();

        subjectFieldTypes.add(SubjectFieldType.COMMON_NAME);
        subjectFieldTypes.add(SubjectFieldType.COUNTRY_NAME);

        return subjectFieldTypes;
    }

    /**
     * Method to provide dummy CertificateExtensions for tests.
     */
    private CertificateExtensions createCertificateExtensions() {
        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        certificateExtensionList.add(createAuthorityInformationAccess());
        certificateExtensionList.add(createAuthorityKeyIdentifier());
        certificateExtensionList.add(createExtendedKeyUsage());
        certificateExtensionList.add(createKeyUsage());
        certificateExtensionList.add(createSubjectAltName());
        certificateExtensionList.add(createSubjectKeyIdentifier());
        certificateExtensionList.add(createBasicConstraints());
        certificateExtensionList.add(createCRLDistributionPoints());
        certificateExtensions.setCertificateExtensions(certificateExtensionList);
        return certificateExtensions;
    }

    /**
     * Method to provide dummy CertificateExtensions for tests.
     */
    public CertificateProfile getCertificateProfile() {
        return certificateProfile;
    }

    /**
     * Method to provide dummy SubjectKeyIdentifier for tests.
     */
    public SubjectKeyIdentifier createSubjectKeyIdentifier() {
        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        subjectKeyIdentifier.setCritical(true);
        final KeyIdentifier keyIdentifier = new KeyIdentifier();
        keyIdentifier.setAlgorithm(new AlgorithmSetUpToTest().getKeyGenerationAlgorithmList().get(0));
        subjectKeyIdentifier.setKeyIdentifier(keyIdentifier);
        return subjectKeyIdentifier;
    }

    /**
     * Method to provide dummy AuthorityKeyIdentifier for tests.
     */
    public AuthorityKeyIdentifier createAuthorityKeyIdentifier() {
        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setSubjectkeyIdentifier(createSubjectKeyIdentifier());
        authorityKeyIdentifier.setType(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);
        authorityKeyIdentifier.setCritical(false);
        return authorityKeyIdentifier;
    }

    /**
     * Method to provide dummy BasicConstraints for tests.
     */
    public BasicConstraints createBasicConstraints() {
        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setIsCA(true);
        basicConstraints.setCritical(true);
        basicConstraints.setPathLenConstraint(0);
        return basicConstraints;
    }

    /**
     * Method to provide dummy AuthorityInformationAccess for tests.
     */
    public AuthorityInformationAccess createAuthorityInformationAccess() {
        final AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        authorityInformationAccess.setAccessDescriptions(null);
        authorityInformationAccess.setCritical(false);
        return authorityInformationAccess;
    }

    /**
     * Method to provide dummy SubjectAltName for tests.
     */
    public SubjectAltName createSubjectAltName() {
        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setCritical(true);
        final List<SubjectAltNameField> subjectAltNameFieldTypes = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField1 = new SubjectAltNameField();
        final SubjectAltNameField subjectAltNameField2 = new SubjectAltNameField();
        subjectAltNameField1.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameFieldTypes.add(subjectAltNameField1);
        subjectAltNameField2.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameFieldTypes.add(subjectAltNameField2);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldTypes);

        return subjectAltName;
    }

    /**
     * Method to provide dummy supported SubjectAltNameTypes for tests.
     */
    public List<SubjectAltNameFieldType> getSubjectAltNameFieldTypes() {

        final List<SubjectAltNameFieldType> subjectAltNameFieldTypes = new ArrayList<SubjectAltNameFieldType>();

        subjectAltNameFieldTypes.add(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameFieldTypes.add(SubjectAltNameFieldType.IP_ADDRESS);

        return subjectAltNameFieldTypes;
    }

    /**
     * Method to provide dummy KeyUsage for tests.
     */
    public KeyUsage createKeyUsage() {
        final KeyUsage keyUsage = new KeyUsage();
        keyUsage.setCritical(true);
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.CRL_SIGN);
        keyUsageTypes.add(KeyUsageType.KEY_CERT_SIGN);
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        return keyUsage;
    }

    /**
     * Method to provide dummy ExtendedKeyUsage for tests.
     */
    public ExtendedKeyUsage createExtendedKeyUsage() {
        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(false);
        final List<KeyPurposeId> keyPurposeIds = new ArrayList<KeyPurposeId>();
        keyPurposeIds.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeIds.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeIds);
        return extendedKeyUsage;
    }

    /**
     * Method to provide dummy CRLDistributionPoints for tests.
     */
    public CRLDistributionPoints createCRLDistributionPoints() {
        final DistributionPoint distributionPoint = new DistributionPoint();
        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        final List<DistributionPoint> crlDistributionPointList = new ArrayList<DistributionPoint>();
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> strNames = new ArrayList<String>();
        strNames.add("ldap://ldap.example.com/cn=Barbara%20Jensen,dc=example,dc=com?cn,mail,telephoneNumber");
        distributionPointName.setFullName(strNames);
        distributionPoint.setDistributionPointName(distributionPointName);

        crlDistributionPointList.add(distributionPoint);
        crlDistributionPoints.setCritical(true);
        crlDistributionPoints.setDistributionPoints(crlDistributionPointList);
        return crlDistributionPoints;
    }

}
