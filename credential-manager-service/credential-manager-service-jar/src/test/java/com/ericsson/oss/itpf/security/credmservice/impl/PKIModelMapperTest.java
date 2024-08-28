/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.Duration;

import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAccessMethod;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithmType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAuthorityInformationAccess;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerBasicConstraints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLDistributionPoints;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateExtensions;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEdiPartyName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerExtendedKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerKeyUsage;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerOtherName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerReasonFlag;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.keymanagement.KeyGenerator;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessDescription;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AccessMethod;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityInformationAccess;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifierType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPoint;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyUsageType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.services.security.pkimock.exception.MockCertificateServiceException;
import com.ericsson.oss.services.security.pkimock.util.CertificateUtils;
import com.ericsson.oss.services.security.pkimock.util.X509CACertificateGenerator;

public class PKIModelMapperTest {

    @Before
    public void setup() {

    }

    @Test
    public void testEndEntityFromPkiToCredM() throws CredentialManagerInvalidEntityException {

        try {
            final CredentialManagerEntity credmEeFail = PKIModelMapper.credMEndEntityFrom(null);
            assertTrue(credmEeFail != null);
        } catch (final CredentialManagerInvalidEntityException e11) {
            assertTrue(e11.getErrorMessage().contains("End Entity is null"));
        }

        final Entity ee = new Entity();

        final EntityInfo entityInfo = new EntityInfo();

        final Subject subject = new Subject();

        final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();

        subjectMap.put(SubjectFieldType.COMMON_NAME, "commonName");
        subjectMap.put(SubjectFieldType.COUNTRY_NAME, "country");
        subjectMap.put(SubjectFieldType.DN_QUALIFIER, "dnName");
        subjectMap.put(SubjectFieldType.GIVEN_NAME, "givenName");
        subjectMap.put(SubjectFieldType.LOCALITY_NAME, "locality");
        subjectMap.put(SubjectFieldType.ORGANIZATION_UNIT, "unitName");
        subjectMap.put(SubjectFieldType.ORGANIZATION, "organizationName");
        subjectMap.put(SubjectFieldType.SERIAL_NUMBER, "serialNumber");
        subjectMap.put(SubjectFieldType.STATE, "state");
        subjectMap.put(SubjectFieldType.STREET_ADDRESS, "streetAddress");
        subjectMap.put(SubjectFieldType.SURNAME, "surname");
        subjectMap.put(SubjectFieldType.TITLE, "title");
        //subject.setStreetAddress("address");

        for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
            final SubjectField subFieldTemp = new SubjectField();
            subFieldTemp.setType(entry.getKey());
            subFieldTemp.setValue(entry.getValue());
            subject.getSubjectFields().add(subFieldTemp);
        }

        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();

        final SubjectAltNameField directoryNameAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> directoryNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final SubjectAltNameString directoryNameAltNameString = new SubjectAltNameString();
        directoryNameAltNameString.setValue("dir1");
        directoryNameList.add(directoryNameAltNameString);
        directoryNameAltNameValue.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        directoryNameAltNameValue.setValue(directoryNameAltNameString);
        subjectAltNameFieldList.add(directoryNameAltNameValue);

        final SubjectAltNameField dNSNameAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> dNSNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final SubjectAltNameString dNSNameAltNameString = new SubjectAltNameString();
        dNSNameAltNameString.setValue("dnsName");
        dNSNameList.add(dNSNameAltNameString);
        dNSNameAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        dNSNameAltNameValue.setValue(dNSNameAltNameString);
        subjectAltNameFieldList.add(dNSNameAltNameValue);

        final SubjectAltNameField ediPartiyNameAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> ediPartyNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final EdiPartyName ediPartyname = new EdiPartyName();
        ediPartyname.setNameAssigner("nameAssigner");
        ediPartyname.setPartyName("partyName");
        ediPartyNameList.add(ediPartyname);
        ediPartiyNameAltNameValue.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        ediPartiyNameAltNameValue.setValue(ediPartyname);
        subjectAltNameFieldList.add(ediPartiyNameAltNameValue);

        final SubjectAltNameField iPAddressAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> iPAddressList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final SubjectAltNameString iPAddressAltNameString = new SubjectAltNameString();
        iPAddressAltNameString.setValue("1.1.1.1");
        iPAddressList.add(iPAddressAltNameString);
        iPAddressAltNameValue.setType(SubjectAltNameFieldType.IP_ADDRESS);
        iPAddressAltNameValue.setValue(iPAddressAltNameString);
        subjectAltNameFieldList.add(iPAddressAltNameValue);

        final SubjectAltNameField otherNameAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> otherNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final OtherName otherName = new OtherName();
        otherName.setTypeId("type");
        otherName.setValue("value");
        otherNameList.add(otherName);
        otherNameAltNameValue.setType(SubjectAltNameFieldType.OTHER_NAME);
        otherNameAltNameValue.setValue(otherName);
        subjectAltNameFieldList.add(otherNameAltNameValue);

        final SubjectAltNameField registeredIDAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> registeredIDList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final SubjectAltNameString value3 = new SubjectAltNameString();
        value3.setValue("registered");
        registeredIDList.add(value3);
        registeredIDAltNameValue.setType(SubjectAltNameFieldType.REGESTERED_ID);
        registeredIDAltNameValue.setValue(value3);
        subjectAltNameFieldList.add(registeredIDAltNameValue);

        final SubjectAltNameField rfc822NameAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> rfc822NameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final SubjectAltNameString value4 = new SubjectAltNameString();
        value4.setValue("rfcName");
        rfc822NameList.add(value4);
        rfc822NameAltNameValue.setType(SubjectAltNameFieldType.RFC822_NAME);
        rfc822NameAltNameValue.setValue(value4);
        subjectAltNameFieldList.add(rfc822NameAltNameValue);

        final SubjectAltNameField uniformResourceIdentifierAltNameValue = new SubjectAltNameField();
        final List<AbstractSubjectAltNameFieldValue> uniformResourceIdentifierList = new ArrayList<>();
        final SubjectAltNameString value5 = new SubjectAltNameString();
        value5.setValue("uri");
        uniformResourceIdentifierList.add(value5);
        uniformResourceIdentifierAltNameValue.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        uniformResourceIdentifierAltNameValue.setValue(value5);
        subjectAltNameFieldList.add(uniformResourceIdentifierAltNameValue);

        //        final SubjectAltNameField x400AddressAltNameValue = new SubjectAltNameField();
        //        final List<AbstractSubjectAltNameFieldValue> x400AddressList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        //        final SubjectAltNameString value6 = new SubjectAltNameString();
        //        value6.setValue("mail@domain");
        //        x400AddressList.add(value6);
        //        x400AddressAltNameValue.setType(SubjectAltNameFieldType.X400_ADDRESS);
        //        x400AddressAltNameValue.setValue(value6);
        //        subjectAltNameFieldList.add(x400AddressAltNameValue);

        final SubjectAltName subjectAltName = new SubjectAltName();
        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldList);
        final CertificateAuthority issuer = new CertificateAuthority();
        final Subject issuer_subj = new Subject();
        issuer.setName("CN=issuer");
        issuer.setSubject(issuer_subj.fromASN1String(issuer.getName()));

        entityInfo.setSubject(subject);
        entityInfo.setSubjectAltName(subjectAltName);
        entityInfo.setIssuer(issuer);
        ee.setEntityInfo(entityInfo);

        final EntityProfile ep1 = new EntityProfile();
        ee.setEntityProfile(ep1);
        ee.getEntityProfile().setName("");
        final Algorithm alg1 = new Algorithm();
        alg1.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        ee.setKeyGenerationAlgorithm(alg1);

        final CredentialManagerEntity credmEe = PKIModelMapper.credMEndEntityFrom(ee);
        Assert.assertEquals("dnName", credmEe.getSubject().getDnQualifier());
    }

    @Test
    public void testProfileInfoFromPkiToCredM() throws CredentialManagerInvalidEntityException, CredentialManagerInvalidProfileException {
        try {
            final CredentialManagerProfileInfo profileFail1 = PKIModelMapper.credMProfileInfoFrom(null, null);
            assertTrue(profileFail1 != null);
        } catch (final CredentialManagerInvalidProfileException e3) {
            assertTrue(e3.getErrorMessage().contains("pki Entity Profile is null"));
        }

        final EntityProfile pkiEntityProfile = new EntityProfile();
        final CertificateProfile pkiCertProfile = new CertificateProfile();
        pkiEntityProfile.setCertificateProfile(pkiCertProfile);
        pkiEntityProfile.getCertificateProfile().setName("certProfilename");
        pkiEntityProfile.setId(1L);
        pkiEntityProfile.setName("name");
        pkiEntityProfile.setType(ProfileType.ENTITY_PROFILE);
        final Subject subject = new Subject();
        pkiEntityProfile.setSubject(subject);

        final SubjectAltName subjectAltName = new SubjectAltName();

        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField e = new SubjectAltNameField();
        e.setType(SubjectAltNameFieldType.IP_ADDRESS);
        final List<AbstractSubjectAltNameFieldValue> value = new ArrayList<AbstractSubjectAltNameFieldValue>();
        final SubjectAltNameString e1 = new SubjectAltNameString();
        e1.setValue("1.1.1.1");
        value.add(e1);
        e.setValue(e1);
        subjectAltNameFieldList.add(e);
        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldList);
        pkiEntityProfile.setSubjectAltNameExtension(subjectAltName);

        pkiEntityProfile.getCertificateProfile().setCertificateExtensions(new CertificateExtensions());

        final Algorithm keyAlg = new Algorithm();
        keyAlg.setKeySize(2048);
        keyAlg.setName("RSA");
        keyAlg.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        keyAlg.setId(12345L);
        keyAlg.setSupported(true);
        keyAlg.setOid("1.2.3.4.5");
        pkiEntityProfile.setKeyGenerationAlgorithm(keyAlg);
        pkiEntityProfile.setTrustProfiles(new ArrayList<TrustProfile>());
        final TrustProfile tpTemp = new TrustProfile();
        tpTemp.setName("trustprof1");
        pkiEntityProfile.getTrustProfiles().add(tpTemp);

        try {
            final CredentialManagerProfileInfo profileFail2 = PKIModelMapper.credMProfileInfoFrom(pkiEntityProfile, null);
            assertTrue(profileFail2 != null);
        } catch (final CredentialManagerInvalidProfileException e3) {
            assertTrue(e3.getErrorMessage().contains("pki Certificate Profile is null"));
        }

        final CertificateExtensions certificateExtensions = new CertificateExtensions();
        pkiCertProfile.setCertificateExtensions(certificateExtensions);
        pkiCertProfile.setVersion(CertificateVersion.V3);
        pkiCertProfile.setId(2L);
        final CAEntity caent1 = new CAEntity();
        final CertificateAuthority caAuth1 = new CertificateAuthority();
        caent1.setCertificateAuthority(caAuth1);
        pkiCertProfile.setIssuer(caent1);
        pkiCertProfile.getIssuer().getCertificateAuthority().setName("issuer");
        pkiCertProfile.setIssuerUniqueIdentifier(true);
        final List<Algorithm> keyAlgList = new ArrayList<>();
        final Algorithm alg = new Algorithm();
        alg.setKeySize(2048);
        alg.setName("RSA");
        alg.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        alg.setId(12345L);
        alg.setSupported(true);
        alg.setOid("1.2.3.4.5");
        keyAlgList.add(alg);
        pkiCertProfile.setKeyGenerationAlgorithms(keyAlgList);
        pkiCertProfile.setName("certificate");
        pkiCertProfile.setType(ProfileType.CERTIFICATE_PROFILE);
        final Algorithm sigAlg = new Algorithm();
        sigAlg.setKeySize(2048);
        sigAlg.setName("SHA256WithRSAEncryption");
        sigAlg.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        sigAlg.setSupported(true);
        pkiCertProfile.setSignatureAlgorithm(sigAlg);

        pkiCertProfile.setSubjectUniqueIdentifier(true);

        pkiCertProfile.setSubjectUniqueIdentifier(false);
        Duration validity = null;
        try {
            validity = DatatypeFactory.newInstance().newDuration("P354D");
        } catch (final DatatypeConfigurationException e2) {
            e2.printStackTrace();
        }
        pkiCertProfile.setCertificateValidity(validity);
        final CredentialManagerProfileInfo profile = PKIModelMapper.credMProfileInfoFrom(pkiEntityProfile, pkiCertProfile);
        Assert.assertEquals(new Integer(2048), profile.getKeyPairAlgorithm().getKeySize());
        Assert.assertEquals("RSA", profile.getKeyPairAlgorithm().getName());
        Assert.assertEquals(CredentialManagerAlgorithmType.ASYMMETRIC_KEY_ALGORITHM, profile.getKeyPairAlgorithm().getType());
        Assert.assertTrue(profile.getKeyPairAlgorithm().isSupported());
        Assert.assertEquals(12345L, profile.getKeyPairAlgorithm().getId());
        Assert.assertEquals("1.2.3.4.5", profile.getKeyPairAlgorithm().getOid());
        Assert.assertEquals("1.1.1.1", profile.getSubjectDefaultAlternativeName().getIPAddress().get(0));
    }

    @Test
    public void testCertificateFromPkiToCredM() throws CredentialManagerCertificateEncodingException, DatatypeConfigurationException,
            CredentialManagerInvalidEntityException, CertificateServiceException {
        try {
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
            final Entity ee = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            final CertificateAuthority issuer = new CertificateAuthority();
            final Subject subject = new Subject();
            final Subject issuer_subj = new Subject();
            final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();
            subjectMap.put(SubjectFieldType.COMMON_NAME, "entityName");

            final SubjectField subFieldTemp = new SubjectField();
            for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
                subFieldTemp.setType(entry.getKey());
                subFieldTemp.setValue(entry.getValue());
                subject.getSubjectFields().add(subFieldTemp);
            }
            issuer.setName("CN=Issuer");
            issuer.setSubject(issuer_subj.fromASN1String(issuer.getName()));
            entityInfo.setSubject(subject);
            entityInfo.setIssuer(issuer);
            ee.setEntityInfo(entityInfo);
            final Attribute[] att = new Attribute[0];
            final PKCS10CertificationRequest csr = CertificateUtils.generatePKCS10Request("SHA256WITHRSAENCRYPTION", ee, keyPair, att, null);
            final X509Certificate cert = X509CACertificateGenerator.generateCertificateFromCA(csr, "issuer",
                    DatatypeFactory.newInstance().newDuration("P365D"));

            if (cert == null) {
                throw new MockCertificateServiceException("Certificate is null");
            }
            com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate pkiCertificate;
            pkiCertificate = new com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate();

            pkiCertificate.setX509Certificate(cert);
            final CredentialManagerX509Certificate credMcertificate = PKIModelMapper.credMCertificateFrom(pkiCertificate);
            Assert.assertNotNull(credMcertificate.retrieveCertificate());

            //Test credMEndEntityCertificatesFrom(EndEntity)
            final EntityProfile ep1 = new EntityProfile();
            ee.setEntityProfile(ep1);
            final CredentialManagerEntityCertificates credMEndEntCertsEmpty = PKIModelMapper.credMEndEntityCertificatesFrom(ee);
            Assert.assertTrue(credMEndEntCertsEmpty.getCerts().isEmpty());

            final List<com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate> inactiveCerts = new ArrayList<com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate>();
            final X509Certificate certActive = X509CACertificateGenerator.generateCertificateFromCA(csr, "issuer",
                    DatatypeFactory.newInstance().newDuration("P365D"));
            if (certActive == null) {
                throw new MockCertificateServiceException("New Active Certificate is null");
            }
            com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate pkiCertAct;
            pkiCertAct = new com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate();

            pkiCertAct.setX509Certificate(certActive);
            inactiveCerts.add(pkiCertificate);
            ee.getEntityInfo().setActiveCertificate(pkiCertAct);
            ee.getEntityInfo().setInActiveCertificates(inactiveCerts);
            final CredentialManagerEntityCertificates credMEndEntCerts = PKIModelMapper.credMEndEntityCertificatesFrom(ee);
            Assert.assertNotNull(credMEndEntCerts.getCerts().get(0));
            Assert.assertNotNull(credMEndEntCerts.getCerts().get(1));

        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testCertificateExtensionsFromPkiToCredM() {
        final CertificateExtensions extensions = createCertificateExtension();

        final CredentialManagerCertificateExtensions credMcertificateExtensions = PKIModelMapper.credMExtensionFrom(extensions);

        final CredentialManagerAuthorityInformationAccess newAuthInfAccess = credMcertificateExtensions.getAuthorityInformationAccess();
        assertNotNull(newAuthInfAccess);
        assertEquals("location", newAuthInfAccess.getAccessDescription().get(0).getAccessLocation());
        assertEquals(CredentialManagerAccessMethod.CA_ISSUER, newAuthInfAccess.getAccessDescription().get(0).getAccessMethod());
        assertEquals(true, newAuthInfAccess.isCritical());

        final CredentialManagerAuthorityKeyIdentifier newAuthorityKeyIdentifier = credMcertificateExtensions.getAuthorityKeyIdentifier();
        assertNotNull(newAuthorityKeyIdentifier);
        assertEquals(true, newAuthorityKeyIdentifier.isCritical());

        final CredentialManagerBasicConstraints newBasicConstraints = credMcertificateExtensions.getBasicConstraints();
        assertNotNull(newBasicConstraints);
        assertEquals(true, newBasicConstraints.isCA());
        assertEquals(10, newBasicConstraints.getPathLenConstraint());
        assertEquals(true, newBasicConstraints.isCritical());

        final CredentialManagerCRLDistributionPoints newCRLDistributionPoint = credMcertificateExtensions.getCrlDistributionPoints();
        assertNotNull(newCRLDistributionPoint);
        assertEquals(true, newCRLDistributionPoint.isCritical());
        assertEquals("CRLIssuer", newCRLDistributionPoint.getCRLDistributionPoints().get(0).getCRLIssuer());
        assertEquals("fullname1", newCRLDistributionPoint.getCRLDistributionPoints().get(0).getDistributionPointName().getFullName().get(0));
        assertEquals("nameRelativeToCRLIssuer",
                newCRLDistributionPoint.getCRLDistributionPoints().get(0).getDistributionPointName().getNameRelativeToCRLIssuer());
        assertEquals(CredentialManagerReasonFlag.SUPERSEDED, newCRLDistributionPoint.getCRLDistributionPoints().get(0).getReasonFlag());

        final CredentialManagerExtendedKeyUsage newExtendedKeyUsage = credMcertificateExtensions.getExtendedKeyUsage();
        assertNotNull(newExtendedKeyUsage);
        assertEquals(true, newExtendedKeyUsage.isCritical());
        assertEquals("id_kp_codeSigning", newExtendedKeyUsage.getKeyPurposeId().get(0).value());

        final CredentialManagerKeyUsage newKeyUsage = credMcertificateExtensions.getKeyUsage();
        assertNotNull(newKeyUsage);
        assertEquals(true, newKeyUsage.isCritical());
        assertEquals("digitalSignature", newKeyUsage.getKeyUsageType().get(0).value());

        final CredentialManagerSubjectKeyIdentifier newSubjectKeyIdentifier = credMcertificateExtensions.getSubjectKeyIdentifier();
        assertNotNull(newSubjectKeyIdentifier);
        assertEquals(true, newSubjectKeyIdentifier.isCritical());

    }

    private CertificateExtensions createCertificateExtension() {
        final CertificateExtensions extensions = new CertificateExtensions();

        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();
        final AuthorityInformationAccess authInfAccess = new AuthorityInformationAccess();
        final List<AccessDescription> descriptionList = new ArrayList<AccessDescription>();
        final AccessDescription description = new AccessDescription();
        description.setAccessLocation("location");
        description.setAccessMethod(AccessMethod.CA_ISSUER);
        descriptionList.add(description);
        authInfAccess.setAccessDescriptions(descriptionList);
        authInfAccess.setCritical(true);
        certificateExtensionList.add(authInfAccess);

        final AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setType(AuthorityKeyIdentifierType.SUBJECT_KEY_IDENTIFIER);
        authorityKeyIdentifier.setCritical(true);
        certificateExtensionList.add(authorityKeyIdentifier);

        final BasicConstraints basicConstraints = new BasicConstraints();
        basicConstraints.setIsCA(true);
        basicConstraints.setPathLenConstraint(10);
        basicConstraints.setCritical(true);
        certificateExtensionList.add(basicConstraints);

        final CRLDistributionPoints crlDistributionPoints = new CRLDistributionPoints();
        crlDistributionPoints.setCritical(true);

        final List<DistributionPoint> DistrPointList = new ArrayList<>();
        final DistributionPoint DistrPoint = new DistributionPoint();
        DistrPoint.setCRLIssuer("CRLIssuer");
        final DistributionPointName distributionPointName = new DistributionPointName();
        final List<String> fullName = new ArrayList<String>();
        fullName.add("fullname1");
        distributionPointName.setFullName(fullName);
        distributionPointName.setNameRelativeToCRLIssuer("nameRelativeToCRLIssuer");
        DistrPoint.setDistributionPointName(distributionPointName);
        DistrPoint.setReasonFlag(ReasonFlag.SUPERSEDED);
        DistrPointList.add(DistrPoint);
        crlDistributionPoints.setDistributionPoints(DistrPointList);

        certificateExtensionList.add(crlDistributionPoints);

        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposedIds = new ArrayList<KeyPurposeId>();
        keyPurposedIds.add(KeyPurposeId.fromValue("id_kp_codeSigning"));
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposedIds);
        extendedKeyUsage.setCritical(true);
        certificateExtensionList.add(extendedKeyUsage);

        final KeyUsage keyUsage = new KeyUsage();
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.fromValue("digitalSignature"));
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsage.setCritical(true);
        certificateExtensionList.add(keyUsage);

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameFieldType> supportedSubjectAltNameField = new ArrayList<SubjectAltNameFieldType>();
        supportedSubjectAltNameField.add(SubjectAltNameFieldType.IP_ADDRESS);
        supportedSubjectAltNameField.add(SubjectAltNameFieldType.DNS_NAME);
        subjectAltName.setCritical(true);
        certificateExtensionList.add(subjectAltName);

        final SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier();
        final KeyIdentifier keyidentifier = new KeyIdentifier();
        final Algorithm algorithm3 = new Algorithm();
        algorithm3.setName("160-BIT_SHA-1");
        keyidentifier.setAlgorithm(algorithm3);
        subjectKeyIdentifier.setKeyIdentifier(keyidentifier);
        subjectKeyIdentifier.setCritical(true);
        certificateExtensionList.add(subjectKeyIdentifier);

        extensions.setCertificateExtensions(certificateExtensionList);
        return extensions;
    }

    private CertificateExtensions createEntityProfileCertificateExtension() {
        final CertificateExtensions extensions = new CertificateExtensions();

        final List<CertificateExtension> certificateExtensionList = new ArrayList<CertificateExtension>();

        final AuthorityInformationAccess authorityInfoAccess = new AuthorityInformationAccess();
        final List<AccessDescription> accessDescriptionList = new ArrayList<AccessDescription>();
        final AccessDescription accDesc = new AccessDescription();
        accDesc.setAccessLocation("Here");
        accDesc.setAccessMethod(AccessMethod.CA_ISSUER);
        accessDescriptionList.add(accDesc);
        authorityInfoAccess.setAccessDescriptions(accessDescriptionList);
        authorityInfoAccess.setCritical(true);
        certificateExtensionList.add(authorityInfoAccess);

        final AuthorityKeyIdentifier authorityKeyId = new AuthorityKeyIdentifier();
        authorityKeyId.setType(AuthorityKeyIdentifierType.ISSUER_DN_SERIAL_NUMBER);
        authorityKeyId.setSubjectkeyIdentifier(new SubjectKeyIdentifier());
        authorityKeyId.setCritical(true);
        certificateExtensionList.add(authorityKeyId);

        final BasicConstraints basicConstraint = new BasicConstraints();
        basicConstraint.setIsCA(true);
        basicConstraint.setCritical(true);
        basicConstraint.setPathLenConstraint(10);
        certificateExtensionList.add(basicConstraint);

        final ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage();
        final List<KeyPurposeId> keyPurposedIds = new ArrayList<KeyPurposeId>();
        keyPurposedIds.add(KeyPurposeId.fromValue("id_kp_OCSPSigning"));
        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposedIds);
        extendedKeyUsage.setCritical(true);
        certificateExtensionList.add(extendedKeyUsage);

        final KeyUsage keyUsage = new KeyUsage();
        final List<KeyUsageType> keyUsageTypes = new ArrayList<KeyUsageType>();
        keyUsageTypes.add(KeyUsageType.fromValue("keyCertSign"));
        keyUsage.setSupportedKeyUsageTypes(keyUsageTypes);
        keyUsage.setCritical(true);
        certificateExtensionList.add(keyUsage);

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameFieldType> supportedSubjectAltNameField = new ArrayList<SubjectAltNameFieldType>();
        supportedSubjectAltNameField.add(SubjectAltNameFieldType.IP_ADDRESS);
        supportedSubjectAltNameField.add(SubjectAltNameFieldType.DNS_NAME);
        subjectAltName.setCritical(true);
        certificateExtensionList.add(subjectAltName);

        final SubjectKeyIdentifier subjectKeyId = new SubjectKeyIdentifier();
        final KeyIdentifier keyId = new KeyIdentifier();
        final Algorithm alg = new Algorithm();
        alg.setKeySize(2048);
        alg.setSupported(true);
        alg.setId(1234);
        alg.setOid("oid");
        alg.setName("algorithm");
        keyId.setAlgorithm(alg);
        keyId.setKeyIdentifer("keyId");
        subjectKeyId.setKeyIdentifier(keyId);
        subjectKeyId.setCritical(true);
        certificateExtensionList.add(subjectKeyId);

        extensions.setCertificateExtensions(certificateExtensionList);
        return extensions;
    }

    @Test
    public void testSubjectAltNameFromCredMToPki() {
        final CredentialManagerSubjectAltName credentialManagerSubjectAltName = new CredentialManagerSubjectAltName();

        final List<String> directoryNameList = new ArrayList<String>();
        directoryNameList.add("directoryName");
        credentialManagerSubjectAltName.setDirectoryName(directoryNameList);
        final List<String> dnsNameList = new ArrayList<String>();
        dnsNameList.add("dns");
        credentialManagerSubjectAltName.setDNSName(dnsNameList);
        final List<String> ipAddress = new ArrayList<String>();
        ipAddress.add("127.0.0.1");
        credentialManagerSubjectAltName.setIPAddress(ipAddress);
        final List<String> registerID = new ArrayList<String>();
        registerID.add("registerID");
        credentialManagerSubjectAltName.setRegisteredID(registerID);
        final List<String> rfc822Name = new ArrayList<String>();
        rfc822Name.add("rfc822Name");
        credentialManagerSubjectAltName.setRfc822Name(rfc822Name);
        final List<String> uniformResourceIdentifier = new ArrayList<String>();
        uniformResourceIdentifier.add("uniformResourceIdentifier");
        uniformResourceIdentifier.add("uniformResourceIdentifier2"); //multiple values of the same type
        credentialManagerSubjectAltName.setUniformResourceIdentifier(uniformResourceIdentifier);
        //        final List<String> x400Address = new ArrayList<String>();
        //        x400Address.add("x400Address");
        //        credentialManagerSubjectAltName.setX400Address(x400Address);
        final List<CredentialManagerEdiPartyName> ediPartyNames = new ArrayList<CredentialManagerEdiPartyName>();
        final CredentialManagerEdiPartyName ediPartyName = new CredentialManagerEdiPartyName();
        ediPartyName.setNameAssigner("ediPartyNameAssigner");
        ediPartyName.setPartyName("PartyName");
        ediPartyNames.add(ediPartyName);
        credentialManagerSubjectAltName.setEdiPartyName(ediPartyNames);
        final List<CredentialManagerOtherName> otherNames = new ArrayList<CredentialManagerOtherName>();
        final CredentialManagerOtherName otherName = new CredentialManagerOtherName();
        otherName.setTypeId("CN=Type");//string value, absolutely non standard
        otherName.setValue("OtherNameValue");
        otherNames.add(otherName);
        credentialManagerSubjectAltName.setOtherName(otherNames);

        final SubjectAltName alternateNameFail = PKIModelMapper.pkiSubjectAltNameFrom(null);
        assertTrue(alternateNameFail == null);

        final SubjectAltName alternateName = PKIModelMapper.pkiSubjectAltNameFrom(credentialManagerSubjectAltName);
        final SubjectAltNameString dirNameValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(0).getValue();
        final SubjectAltNameString dnsValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(1).getValue();
        final SubjectAltNameString ipAddressValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(2).getValue();
        final SubjectAltNameString registerIDValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(3).getValue();
        final SubjectAltNameString rfc822NameValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(4).getValue();
        final SubjectAltNameString uniformResourceIdentifierValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(5).getValue();
        final SubjectAltNameString uniformResourceIdentifierValue2 = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(6).getValue();
        //        final SubjectAltNameString x400AddressValue = (SubjectAltNameString) alternateName.getSubjectAltNameFields().get(7).getValue();
        //        final EdiPartyName ediPartyNameValue = (EdiPartyName) alternateName.getSubjectAltNameFields().get(8).getValue();
        //        final OtherName otherNameValue = (OtherName) alternateName.getSubjectAltNameFields().get(9).getValue();
        final EdiPartyName ediPartyNameValue = (EdiPartyName) alternateName.getSubjectAltNameFields().get(7).getValue();
        final OtherName otherNameValue = (OtherName) alternateName.getSubjectAltNameFields().get(8).getValue();
        assertEquals("directoryName", dirNameValue.getValue());
        assertEquals("dns", dnsValue.getValue());
        assertEquals("127.0.0.1", ipAddressValue.getValue());
        assertEquals("registerID", registerIDValue.getValue());
        assertEquals("rfc822Name", rfc822NameValue.getValue());
        assertEquals("uniformResourceIdentifier", uniformResourceIdentifierValue.getValue());
        assertEquals("uniformResourceIdentifier2", uniformResourceIdentifierValue2.getValue());
        //        assertEquals("x400Address", x400AddressValue.getValue());
        assertEquals("ediPartyNameAssigner", ediPartyNameValue.getNameAssigner());
        assertEquals("PartyName", ediPartyNameValue.getPartyName());
        assertEquals("CN=Type", otherNameValue.getTypeId());
        assertEquals("OtherNameValue", otherNameValue.getValue());

        //        assertEquals(true, alternateName.isCritical());
    }

    @Test
    public void testSubjectFromCredMToPki() {
        final CredentialManagerSubject credMSubject = new CredentialManagerSubject();
        credMSubject.setCommonName("commonName");
        credMSubject.setCountryName("countryName");
        credMSubject.setDnQualifier("dnQualifier");
        credMSubject.setGivenName("givenName");
        credMSubject.setLocalityName("localityName");
        credMSubject.setStreetAddress("streetAddress");
        credMSubject.setOrganizationalUnitName("organizationalUnitName");
        credMSubject.setOrganizationName("organizationName");
        credMSubject.setSerialNumber("serialNumber");
        credMSubject.setStateOrProvinceName("stateOrProvinceName");
        credMSubject.setSurName("surName");
        credMSubject.setTitle("title");
        final Subject subjectFail = PKIModelMapper.pkiSubjectFrom(null);
        assertTrue(subjectFail == null);
        final Subject subject = PKIModelMapper.pkiSubjectFrom(credMSubject);

        Assert.assertEquals("commonName", subject.getSubjectFields().get(0).getValue());
        Assert.assertEquals("countryName", subject.getSubjectFields().get(1).getValue());
        Assert.assertEquals("dnQualifier", subject.getSubjectFields().get(2).getValue());
        Assert.assertEquals("givenName", subject.getSubjectFields().get(3).getValue());
        Assert.assertEquals("localityName", subject.getSubjectFields().get(4).getValue());
        Assert.assertEquals("organizationalUnitName", subject.getSubjectFields().get(5).getValue());
        Assert.assertEquals("organizationName", subject.getSubjectFields().get(6).getValue());
        Assert.assertEquals("serialNumber", subject.getSubjectFields().get(7).getValue());
        Assert.assertEquals("stateOrProvinceName", subject.getSubjectFields().get(8).getValue());
        Assert.assertEquals("surName", subject.getSubjectFields().get(9).getValue());
        Assert.assertEquals("streetAddress", subject.getSubjectFields().get(10).getValue());
        Assert.assertEquals("title", subject.getSubjectFields().get(11).getValue());
    }

    @Test
    public void testCSRFromCredMToPki() {
        try {
            final KeyPair keyPair = KeyGenerator.getKeyPair("RSA", 2048);
            final Entity ee = new Entity();
            final EntityInfo entityInfo = new EntityInfo();

            final Subject subject = new Subject();
            final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();
            subjectMap.put(SubjectFieldType.COMMON_NAME, "endEntityName");

            final SubjectField subfiTemp = new SubjectField();
            for (final Entry<SubjectFieldType, String> entry : subjectMap.entrySet()) {
                subfiTemp.setType(entry.getKey());
                subfiTemp.setValue(entry.getValue());
                subject.getSubjectFields().add(subfiTemp);
            }

            entityInfo.setSubject(subject);
            ee.setEntityInfo(entityInfo);
            final PKCS10CertificationRequest csr = CertificateUtils.generatePKCS10Request("SHA256WITHRSAENCRYPTION", ee, keyPair, null, null);
            final CredentialManagerPKCS10CertRequest credMCSR = new CredentialManagerPKCS10CertRequest(csr);
            Assert.assertNotNull(credMCSR.getRequest());
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | IOException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testCredMExtensionFromCertAndEntity() {
        final CertificateExtensions certProfileExt = createCertificateExtension();
        final CertificateExtensions entityProfileExt = createEntityProfileCertificateExtension();

        final CredentialManagerCertificateExtensions credMcertificateExtensions = PKIModelMapper.credMExtensionFrom(certProfileExt, entityProfileExt);

        final CredentialManagerAuthorityKeyIdentifier newAuthorityKeyIdentifier = credMcertificateExtensions.getAuthorityKeyIdentifier();
        assertNotNull(newAuthorityKeyIdentifier);
        assertEquals(true, newAuthorityKeyIdentifier.isCritical());

        final CredentialManagerBasicConstraints newBasicConstraints = credMcertificateExtensions.getBasicConstraints();
        assertNotNull(newBasicConstraints);
        assertEquals(true, newBasicConstraints.isCA());
        assertEquals(10, newBasicConstraints.getPathLenConstraint());
        assertEquals(true, newBasicConstraints.isCritical());
        final CredentialManagerCRLDistributionPoints newCRLDistributionPoint = credMcertificateExtensions.getCrlDistributionPoints();
        assertNotNull(newCRLDistributionPoint);
        assertEquals(true, newCRLDistributionPoint.isCritical());
        assertEquals("CRLIssuer", newCRLDistributionPoint.getCRLDistributionPoints().get(0).getCRLIssuer());
        assertEquals("fullname1", newCRLDistributionPoint.getCRLDistributionPoints().get(0).getDistributionPointName().getFullName().get(0));
        assertEquals("nameRelativeToCRLIssuer",
                newCRLDistributionPoint.getCRLDistributionPoints().get(0).getDistributionPointName().getNameRelativeToCRLIssuer());
        assertEquals(CredentialManagerReasonFlag.SUPERSEDED, newCRLDistributionPoint.getCRLDistributionPoints().get(0).getReasonFlag());

        final CredentialManagerExtendedKeyUsage newExtendedKeyUsage = credMcertificateExtensions.getExtendedKeyUsage();
        assertNotNull(newExtendedKeyUsage);
        assertEquals(true, newExtendedKeyUsage.isCritical());
        assertEquals("id_kp_OCSPSigning", newExtendedKeyUsage.getKeyPurposeId().get(0).value());

        final CredentialManagerKeyUsage newKeyUsage = credMcertificateExtensions.getKeyUsage();
        assertNotNull(newKeyUsage);
        assertEquals(true, newKeyUsage.isCritical());
        assertEquals("keyCertSign", newKeyUsage.getKeyUsageType().get(0).value());

        final CredentialManagerSubjectKeyIdentifier newSubjectKeyIdentifier = credMcertificateExtensions.getSubjectKeyIdentifier();
        assertNotNull(newSubjectKeyIdentifier);
        assertEquals(true, newSubjectKeyIdentifier.isCritical());

    }

}
