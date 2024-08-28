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

package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.xml.datatype.Duration;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.mockito.Mock;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator.CertificateGenerator;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.KeyIdentifierData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;

public class BaseTest {

    @Mock
    protected Logger logger;

    @Mock
    protected CertificateGenerator certGenerator;

    @Mock
    protected SystemRecorder systemRecorder;

    @Mock
    protected CertificateGenerationInfoParser certGenInfoParser;

    @Mock
    protected CertificatePersistenceHelper persistenceHelper;

    @Mock
    protected CertificateModelMapper modelMapper;

    public final static String CERTIFICATE_TYPE = "X.509";
    public final static String ROOT_CA = "ENM_RootCA";
    public final static String SUB_CA = "ENM_SubCA";
    public final static String OTP = "OneTimePassword";
    public final static String entityName = "ERBS_Node";

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    public static final String KEY_GEN_ALGORITHM = "RSA";
    private static final String PROVIDER = "BC";

    /**
     * Method to get {@link X509Certificate} from certificate file.
     * 
     * @param filename
     *            name of certificate file.
     * @return X509Certificate object.
     * @throws IOException
     *             {@link IOException}
     * @throws CertificateException
     *             {@link CertificateException}
     */
    protected X509Certificate getCertificate(final String filename) throws IOException, CertificateException {
        final FileInputStream fin = new FileInputStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fin);
        return certificate;
    }

    /**
     * Method to prepare {@link Algorithm} model for key generation.
     * 
     * @return Algorithm model.
     */
    protected Algorithm prepareKeyGenerationAlgorithm() {
        final Algorithm keyGenerationAlgorithm = new Algorithm();
        keyGenerationAlgorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        keyGenerationAlgorithm.setName("RSA");
        keyGenerationAlgorithm.setKeySize(2048);
        return keyGenerationAlgorithm;
    }

    /**
     * Method to prepare {@link Algorithm} model for key generation.
     * 
     * @return Algorithm model.
     */
    protected Algorithm prepareKeyIdentifierAlgorithm(final String keyIdentifierType) {
        final Algorithm keyGenerationAlgorithm = new Algorithm();
        keyGenerationAlgorithm.setType(AlgorithmType.MESSAGE_DIGEST_ALGORITHM);
        keyGenerationAlgorithm.setName(keyIdentifierType);
        return keyGenerationAlgorithm;
    }

    /**
     * Method to prepare {@link Algorithm} model for signature..
     * 
     * @return Algorithm model.
     */
    protected Algorithm prepareSignatureAlgorithm() {
        final Algorithm signatureAlgorithm = new Algorithm();
        signatureAlgorithm.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        signatureAlgorithm.setName("SHA1withRSA");
        return signatureAlgorithm;
    }

    /**
     * Method to prepare Root CA or SubCA data based on the flag isRootCA passed to it.
     * 
     * @param isRootCA
     *            flag indicating RootCA or not.
     * @return CertificateAuthority for RootCA or SubCA.
     */
    protected CertificateAuthority prepareCAData(final boolean isRootCA) {
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        if (isRootCA) {
            certificateAuthority.setName(ROOT_CA);
        } else {
            certificateAuthority.setName(SUB_CA);
        }
        certificateAuthority.setRootCA(isRootCA);
        certificateAuthority.setSubject(prepareSubject());
        certificateAuthority.setSubjectAltName(prepareSubjectAltName());
        return certificateAuthority;
    }

    /**
     * Method to prepare Certificate data.
     * 
     * @return CertificateData entity.
     */
    protected CertificateData prepareCertificateData() {
        final CertificateData certificateData = new CertificateData();
        certificateData.setNotAfter(new Date());
        certificateData.setNotAfter(new Date());
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateData.setSerialNumber("123");
        return certificateData;
    }

    /**
     * Method to prepare {@link EntityInfo} model.
     * 
     * @return CertificateGenerationInfo model.
     */
    protected EntityInfo prepareEntityInfo() {
        final EntityInfo entityInfo = new EntityInfo();

        entityInfo.setName(entityName);
        entityInfo.setSubject(prepareSubject());
        entityInfo.setSubjectAltName(prepareSubjectAltName());
        entityInfo.setOTP(OTP);
        entityInfo.setOTPCount(5);

        return entityInfo;
    }

    /**
     * Method to generate {@link KeyPair}.
     * 
     * @param keyPairAlgorithm
     *            name of key generation algorithm.
     * @param KeySize
     *            keySize for key generation.
     * @return KeyPair generated.
     * @throws NoSuchAlgorithmException
     *             {@link NoSuchAlgorithmException}
     */
    protected KeyPair generateKeyPair(final String keyPairAlgorithm, final int KeySize) throws NoSuchAlgorithmException {
        KeyPair keyPair = null;
        final java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance(keyPairAlgorithm);
        gen.initialize(KeySize);
        keyPair = gen.generateKeyPair();

        return keyPair;
    }

    /**
     * Prepares Subject model with dummy values.
     * 
     * @return Subject model with dummy values.
     */
    protected Subject prepareSubject() {

        final Subject subject = new Subject();

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField common_name = new SubjectField();
        common_name.setType(SubjectFieldType.COMMON_NAME);
        common_name.setValue("ERBS_node");

        final SubjectField organization = new SubjectField();
        organization.setType(SubjectFieldType.ORGANIZATION);
        organization.setValue("ENM");

        final SubjectField organizationUnit = new SubjectField();
        organizationUnit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        organizationUnit.setValue("Ericsson");

        subjectFields.add(common_name);
        subjectFields.add(organization);
        subjectFields.add(organizationUnit);

        subject.setSubjectFields(subjectFields);

        return subject;
    }

    /**
     * Prepares SubjectAltNameValues with dummy values.
     * 
     * @return
     */
    protected SubjectAltName prepareSubjectAltName() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final SubjectAltNameField dns_name = new SubjectAltNameField();
        final SubjectAltNameField other_name = new SubjectAltNameField();
        final SubjectAltNameField edi_party_name = new SubjectAltNameField();

        final SubjectAltNameString dns_name_value = new SubjectAltNameString();
        dns_name_value.setValue("www.ericsson.com");

        dns_name.setType(SubjectAltNameFieldType.DNS_NAME);
        dns_name.setValue(dns_name_value);

        final EdiPartyName editPartyNanme = new EdiPartyName();
        editPartyNanme.setNameAssigner("EditPartyAssigner");
        editPartyNanme.setPartyName("EditPartyName");

        edi_party_name.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        edi_party_name.setValue(editPartyNanme);

        final OtherName otherName = new OtherName();
        otherName.setTypeId("1");
        otherName.setValue("otherName");

        other_name.setType(SubjectAltNameFieldType.OTHER_NAME);
        other_name.setValue(otherName);

        subjectAltNameFields.add(dns_name);
        subjectAltNameFields.add(edi_party_name);
        subjectAltNameFields.add(other_name);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    public Date addDurationToDate(final Date date, final Duration duration) {

        final Calendar cal = Calendar.getInstance();
        cal.setTime(date);
        cal.add(Calendar.YEAR, duration.getYears());
        cal.add(Calendar.MONTH, duration.getMonths());
        cal.add(Calendar.DAY_OF_MONTH, duration.getDays());
        cal.add(Calendar.HOUR, duration.getHours());
        cal.add(Calendar.MINUTE, duration.getMinutes());
        cal.add(Calendar.SECOND, duration.getSeconds());

        final Date dateAfterDuration = cal.getTime();
        return dateAfterDuration;
    }

    public void assertExtensionValue(final DEROctetString expectedExtension, final Extension actualExtension) {
        assertNotNull(actualExtension);
        assertTrue(actualExtension.isCritical());
        assertEquals(expectedExtension, actualExtension.getExtnValue());
    }

    /**
     * Method to generate PKCS10CertificationRequest using list of generalNames.
     * 
     * @param generalNames
     *            list of GeneralName values.
     * @return PKCS10CertificationRequest PKCS10CertificateRequest object prepared from list of general names.
     * @throws NoSuchAlgorithmException
     * @throws SignatureException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws OperatorCreationException
     */
    public PKCS10CertificationRequest generatePKCS10Request(final List<GeneralName> generalNames) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException,
            NoSuchProviderException, OperatorCreationException {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM, PROVIDER);
        kpg.initialize(1024);
        final KeyPair kp = kpg.genKeyPair();

        final X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, ROOT_CA);
        final X500Name subject = x500NameBld.build();

        final PKCS10CertificationRequestBuilder requestBuilder = createPKCS10ReqBuilder(generalNames, kp, subject);
        return requestBuilder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(kp.getPrivate()));

    }

    /**
     * Method to create PKCS10CertificationRequestBuilder by passing list of generalNames, KeyPair, subject.
     * 
     * @param generalNames
     *            list of generalNames to add into the extension
     * @param kp
     *            KeyPair object.
     * @param subject
     *            subject value passed to create PKCS10CertificationRequestBuilder
     * @return returns generated PKCS10CertificationRequestBuilder object.
     * @throws IOException
     */
    private PKCS10CertificationRequestBuilder createPKCS10ReqBuilder(final List<GeneralName> generalNames, final KeyPair kp, final X500Name subject) throws IOException {
        final PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());

        final ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames.toArray(new GeneralName[0])));
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        return requestBuilder;
    }

    /**
     * This methods prepares object for {@link KeyIdentifierData}
     * 
     * @return object of {@link KeyIdentifierData}
     */
    protected KeyIdentifierData prepareKeyIdentifierData() {

        final KeyIdentifierData keyIdentifierData = new KeyIdentifierData();
        keyIdentifierData.setId(1L);
        keyIdentifierData.setKeyIdentifier("K0000001");
        keyIdentifierData.setStatus(KeyPairStatus.ACTIVE);

        return keyIdentifierData;
    }

    /**
     * This methods prepares KeyUsage extension of bouncy castle and returns it.
     * 
     * @return {@link org.bouncycastle.asn1.x509.KeyUsage}
     */
    protected org.bouncycastle.asn1.x509.KeyUsage prepareKeyUsage_BouncyCastle() {

        final org.bouncycastle.asn1.x509.KeyUsage keyUsage = new org.bouncycastle.asn1.x509.KeyUsage(org.bouncycastle.asn1.x509.KeyUsage.cRLSign | org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                | org.bouncycastle.asn1.x509.KeyUsage.digitalSignature);
        return keyUsage;
    }

    /**
     * This methods prepares Basic Constraints extension of bouncy castle and returns it.
     * 
     * @return {@link org.bouncycastle.asn1.x509.BasicConstraints}
     */
    protected org.bouncycastle.asn1.x509.BasicConstraints prepareBasicConstraints_BouncyCastle() {

        final org.bouncycastle.asn1.x509.BasicConstraints basicConstraints = new org.bouncycastle.asn1.x509.BasicConstraints(true);

        return basicConstraints;
    }

}
