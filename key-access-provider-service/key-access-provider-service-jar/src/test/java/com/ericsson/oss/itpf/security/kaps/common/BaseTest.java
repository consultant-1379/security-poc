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

package com.ericsson.oss.itpf.security.kaps.common;

import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import javax.xml.datatype.Duration;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.mockito.Mock;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.common.exception.SignatureException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

public abstract class BaseTest {
    
    public final static String CERTIFICATE_TYPE = "X.509";
    public final static String ROOT_CA = "ENM_RootCA";
    public final static String SUB_CA = "ENM_SubCA";
    public final static String OTP = "OneTimePassword";
    public final static String entityName = "ERBS_Node";
    
    @Mock
    protected Logger logger;

    @Mock
    protected SystemRecorder systemRecorder;
    
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
        signatureAlgorithm.setKeySize(1024);
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

    public ContentSigner getContentSigner(final PrivateKey privateKey, final String signatureAlgorithm) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, SignatureException {

        try {
            final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
            return contentSigner;
        } catch (OperatorCreationException operatorCreationException) {
            throw new SignatureException(operatorCreationException);
        }
    }
}
