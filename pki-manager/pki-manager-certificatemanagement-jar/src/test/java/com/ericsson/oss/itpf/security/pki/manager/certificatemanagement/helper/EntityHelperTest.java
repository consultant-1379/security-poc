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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.common.certificatemanagement.generator.KeyPairGenerator;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override.SubAltNameOverrider;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override.SubjectOverrider;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

@RunWith(MockitoJUnitRunner.class)
public class EntityHelperTest {

    @InjectMocks
    EntityHelper entityHelper;

    @Mock
    CSRBuilder cSRBuilder;

    @Mock
    KeyPairGenerator keyPairGenerator;
    
    @Mock
    EntityPersistenceHandler<Entity> entityPersistenceHandler;
    
    @Mock
    Logger logger;

    @Mock
    SubjectOverrider subjectOverrider;

    @Mock
    SubAltNameOverrider subAltNameOverrider;

    private static SetUPData setUPData;
    private static EntitySetUPData entitySetUPData;
    private static SubjectSetUPData subjectData;
    private static SubjectAltNameSetUPData subjectAltNameData;
    private static PKCS10CertificationRequestSetUPData pKCS10CertificationRequestSetUP;
    private static List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();
    
    final String ECDSAkeyGeneAlgorithm = "ECDSA";
    Integer keySize = null;
    
    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @Before
    public void setUP() {

        setUPData = new SetUPData();
        subjectData = new SubjectSetUPData();
        entitySetUPData = new EntitySetUPData();
        subjectAltNameData = new SubjectAltNameSetUPData();
        pKCS10CertificationRequestSetUP = new PKCS10CertificationRequestSetUPData();

    }

    /**
     * Test case for verifying the generation of PKCS10Request for an Entity.
     * 
     * @throws Exception
     */
    @Test
    public void testGeneratePKCS10Request() throws Exception {

        final Entity entity = entitySetUPData.getEntity();

        final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);

        mockPKCS10Request(entity, keyPair);

        entityHelper.generatePKCS10Request(entity, keyPair);

    }

    /**
     * Method to test Occurrence of CertificateRequestGenerationException.
     * 
     * @throws Exception
     */
    @Test
    public void testGeneratePKCS10Request_CertificateRequestGenerationException_FromInvalidKeyException() throws Exception {

        try {
            final Entity entity = entitySetUPData.getEntity();

            final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);

            final Algorithm signatureAlgorithm = entity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm();
            final String subjectDN = entity.getEntityInfo().getSubject().toASN1String();

            Mockito.when(cSRBuilder.generatePKCS10Request(new X500Name(subjectDN), keyPair, signatureAlgorithm.getName(), null)).thenThrow(new InvalidKeyException());

            entityHelper.generatePKCS10Request(entity, keyPair);

        } catch (CertificateRequestGenerationException certificateRequestGenerationException) {
            assertTrue(certificateRequestGenerationException.getMessage().toString().contains(ErrorMessages.CSR_KEY_INVALID));
        }

    }

    /**
     * Method to test Occurrence of NoSuchAlgorithmException.
     * 
     * @throws Exception
     */
    @Test
    public void testGeneratePKCS10Request_CertificateRequestGenerationException_FromNoSuchAlgorithmException() throws Exception {

        try {
            final Entity entity = entitySetUPData.getEntity();

            final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);

            final Algorithm signatureAlgorithm = entity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm();
            final String subjectDN = entity.getEntityInfo().getSubject().toASN1String();

            Mockito.when(cSRBuilder.generatePKCS10Request(new X500Name(subjectDN), keyPair, signatureAlgorithm.getName(), null)).thenThrow(new NoSuchAlgorithmException());

            entityHelper.generatePKCS10Request(entity, keyPair);

        } catch (CertificateRequestGenerationException certificateRequestGenerationException) {
            assertTrue(certificateRequestGenerationException.getMessage().toString().contains(ErrorMessages.ALGORITHM_IS_NOT_FOUND));
        }

    }

    /**
     * Method to test Occurrence of SignatureException.
     * 
     * @throws Exception
     */
    @Test
    public void testGeneratePKCS10Request_CertificateRequestGenerationException_FromSignatureException() throws Exception {

        try {
            final Entity entity = entitySetUPData.getEntity();

            final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);

            final Algorithm signatureAlgorithm = entity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm();
            final String subjectDN = entity.getEntityInfo().getSubject().toASN1String();

            Mockito.when(cSRBuilder.generatePKCS10Request(new X500Name(subjectDN), keyPair, signatureAlgorithm.getName(), null)).thenThrow(new SignatureException());

            entityHelper.generatePKCS10Request(entity, keyPair);

        } catch (CertificateRequestGenerationException certificateRequestGenerationException) {
            assertTrue(certificateRequestGenerationException.getMessage().toString().contains(ErrorMessages.CSR_SIGNATURE_GENERATION_FAILED));
        }

    }

    /**
     * Method to test Occurrence of IOException.
     * 
     * @throws Exception
     */
    @Test
    public void testGeneratePKCS10Request_CertificateRequestGenerationException_FromIOException() throws Exception {

        try {
            final Entity entity = entitySetUPData.getEntity();

            final KeyPair keyPair = setUPData.generateKeyPair("RSA", 1024);

            final Algorithm signatureAlgorithm = entity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm();
            final String subjectDN = entity.getEntityInfo().getSubject().toASN1String();

            Mockito.when(cSRBuilder.generatePKCS10Request(new X500Name(subjectDN), keyPair, signatureAlgorithm.getName(), null)).thenThrow(new IOException());

            entityHelper.generatePKCS10Request(entity, keyPair);

        } catch (CertificateRequestGenerationException certificateRequestGenerationException) {
            assertTrue(certificateRequestGenerationException.getMessage().toString().contains(ErrorMessages.CSR_ENCODING_FAILED));
        }

    }

    /**
     * Test case for verifying the generation of KeyPair for an Entity.
     * 
     * @throws Exception
     */
    @Test
    public void testGenerateKeyPair() throws Exception {

        final Algorithm keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");

        final KeyPair expectedKeyPair = setUPData.generateKeyPair("RSA", 2048);
        Mockito.when(keyPairGenerator.generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize())).thenReturn(expectedKeyPair);

        final KeyPair actualKeyPair = entityHelper.generateKeyPair(keyGenerationAlgorithm);
        assertEquals(expectedKeyPair, actualKeyPair);

    }

    /**
     * Test case for verifying KeyPairGenerationException.
     * 
     * @throws Exception
     */
    @Test(expected = KeyPairGenerationException.class)
    public void testGenerateKeyPair_KeyPairGenerationException() throws Exception {

        final Algorithm keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA123");

        Mockito.when(keyPairGenerator.generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize())).thenThrow(
                new NoSuchAlgorithmException(ErrorMessages.ALGORITHM_IS_NOT_FOUND));

        entityHelper.generateKeyPair(keyGenerationAlgorithm);

    }

    /**
     * Test case for verifying getEntity.
     * 
     * @throws DatatypeConfigurationException
     * @throws IOException 
     * @throws CertificateException 
     */
    @Test
    public void testGetEntity() throws DatatypeConfigurationException, CertificateException, IOException {

        final Entity expectedEntity = entitySetUPData.getEntity();

        Mockito.when(entityPersistenceHandler.getEntityForCertificateGeneration(Mockito.any(Entity.class))).thenReturn(expectedEntity);

        final Entity actualEntity = entityHelper.getEntity(SetUPData.ENTITY_NAME);

        assertEquals(expectedEntity, actualEntity);
    }

    /**
     * method to test Occurrence of CertificateServiceException.
     * 
     * @throws DatatypeConfigurationException
     * @throws CertificateServiceException
     */
    @Test(expected = CertificateServiceException.class)
    public void testGetEntity_CertificateServiceException() throws DatatypeConfigurationException {

        Mockito.when(entityPersistenceHandler.getEntityForCertificateGeneration(Mockito.any(Entity.class))).thenThrow(new EntityServiceException("CertificateServiceException"));

        entityHelper.getEntity(SetUPData.ENTITY_NAME);

    }

    /**
     * Test case for verifying getEntity.
     * 
     * @throws DatatypeConfigurationException
     * @throws IOException 
     * @throws CertificateException 
     */
    @Test
    public void testGetEntity_EntityNotFoundException() throws DatatypeConfigurationException, CertificateException, IOException {

        final Entity entity = entitySetUPData.getEntity();
        Mockito.when(entityPersistenceHandler.getEntity(entity)).thenThrow(new EntityNotFoundException());

        entityHelper.getEntity(SetUPData.ENTITY_NAME);

    }

    /**
     * Test case for verifying csr key generation algorithm is matched with entity key generation algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testValidateAndGetAlgorithmModel_Entity_KeyGenAlgorithm_Matched() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        entityHelper.validateAndGetAlgorithmModel(entity, "RSA");

        assertEquals("RSA", entity.getKeyGenerationAlgorithm().getName());

    }

    /**
     * Test case for verifying InvalidCertificateRequestException if csr key generation algorithm is not matched with entity key generation algorithm.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidateAndGetAlgorithmModel_Entity_KeyGenAlgorithm_Not_Matched() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);
        entity.setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("DSA"));

        entityHelper.validateAndGetAlgorithmModel(entity, "RSA");
    }

    /**
     * Test case for verifying csr key generation algorithm is matched with entity profile key generation algorithm.
     * 
     * @throws Exception
     */
    @Test
    public void testValidateAndGetAlgorithmModel_EntityProfile_KeyGenAlgorithm_Matched() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);
        entity.getEntityProfile().setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("RSA"));

        entityHelper.validateAndGetAlgorithmModel(entity, "RSA");

        assertEquals("RSA", entity.getEntityProfile().getKeyGenerationAlgorithm().getName());

    }

    /**
     * Test case for return keyAlgorithms size is Empty.
     * 
     * @throws Exception
     */
    @Test
    public void testValidateAndGetAlgorithmModel_ReturnsNull() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);

        entity.getEntityProfile().getCertificateProfile().setKeyGenerationAlgorithms(keygenerationAlgorithms);

        entityHelper.validateAndGetAlgorithmModel(entity, "RSA");

        assertEquals(0, entity.getEntityProfile().getCertificateProfile().getKeyGenerationAlgorithms().size());

    }

    /**
     * Test case for verifying InvalidCertificateRequestException if csr key generation algorithm is not matched with entity profile key generation algorithm.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidateAndGetAlgorithmModel_EntityProfile_KeyGenAlgorithm_Not_Matched() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);
        entity.getEntityProfile().setKeyGenerationAlgorithm(setUPData.getKeyGenerationAlgorithm("DSA"));

        entityHelper.validateAndGetAlgorithmModel(entity, "RSA");

    }

    /**
     * Test case for verifying csr key generation algorithm is present in the certificate profile key generation algorithms list.
     * 
     * @throws Exception
     */
    @Test
    public void testValidateAndGetAlgorithmModel_CertificateProfile_KeyGenAlgorithm_Matched() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);
        entity.getEntityProfile().getCertificateProfile().setKeyGenerationAlgorithms(Arrays.asList(setUPData.getKeyGenerationAlgorithm("RSA"), setUPData.getKeyGenerationAlgorithm("DSA")));

        entityHelper.validateAndGetAlgorithmModel(entity, "RSA");

        assertEquals("RSA", entity.getEntityProfile().getCertificateProfile().getKeyGenerationAlgorithms().get(0).getName());

    }

    /**
     * Test case for verifying InvalidCertificateRequestException if csr key generation algorithm is not present in the certificate profile key generation algorithms list.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidateAndGetAlgorithmModel_CertificateProfile_KeyGenAlgorithm_Not_Matched() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);
        entity.getEntityProfile().getCertificateProfile().setKeyGenerationAlgorithms(Arrays.asList(setUPData.getKeyGenerationAlgorithm("RSA"), setUPData.getKeyGenerationAlgorithm("DSA")));

        entityHelper.validateAndGetAlgorithmModel(entity, "DES");

    }

    /**
     * Test Case for verifying override entity subject which contains override operator.
     * 
     * @throws Exception
     */

    @Test
    public void testSetEntitySubject_withOverrideOperator() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "?", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);

        final X500Name x500Name = new X500Name("OU=PKICore");
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(x500Name, null);
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        Mockito.when(subjectOverrider.overrideSubject(subject, certificateRequest)).thenReturn(subjectData.getSubject("Test", "Cyberdyne"));

        entityHelper.setEntitySubject(certificateRequest, entity);

        Mockito.verify(subjectOverrider).overrideSubject(subject, certificateRequest);

    }

    /**
     * Test Case for verifying override entity subject without override operator.
     * 
     * @throws Exception
     */

    @Test
    public void testSetEntitySubject_withOutOverrideOperator() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);

        final X500Name name = new X500Name("OU=PKICore");
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, null);
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        entityHelper.setEntitySubject(certificateRequest, entity);

    }

    /**
     * Test Case for verifying override entity SubjectAltName with override operator.
     * 
     * @throws Exception
     */
    @Test
    public void testSetEntitySubjectAltName_withOverrideOperator() throws Exception {

        final SubjectAltName subjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir3", "?");
        final Entity entity = setUPData.getEntity(null, subjectAltName);

        final X500Name name = new X500Name("CN=RootCA");
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, "dir2");
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        final SubjectAltName expectedSAN = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3");
        Mockito.when(subAltNameOverrider.overrideSubjectAltName(subjectAltName, certificateRequest)).thenReturn(expectedSAN);

        entityHelper.setEntitySubjectAltName(certificateRequest, entity);

        Mockito.verify(subAltNameOverrider).overrideSubjectAltName(subjectAltName, certificateRequest);

    }

    /**
     * Test Case for verifying override entity SubjectAltName without override operator.
     * 
     * @throws Exception
     */

    @Test
    public void testSetEntitySubjectAltName_withOutOverrideOperator() throws Exception {

        final SubjectAltName subjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3");
        final Entity entity = setUPData.getEntity(null, subjectAltName);

        final X500Name name = new X500Name("CN=RootCA");
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, null);
        final CertificateRequest certificateRequest = getCertificateRequest(pKCS10CertificationRequest);

        entityHelper.setEntitySubjectAltName(certificateRequest, entity);

    }

    /**
     * Test Case for verifying subject contains override operator.
     * 
     * @throws Exception
     */
    @Test
    public void testIsSubjectContainsOverrideOperator() throws Exception {

        final Subject subject = subjectData.getSubject("Test", "?", "Cyberdyne");
        final Entity entity = setUPData.getEntity(subject, null);

        entityHelper.isSubjectContainsOverrideOperator(entity);

    }

    /**
     * Test Case for verifying EdiPartyName contains override operator.
     * 
     * @throws Exception
     */
    @Test
    public void testIsSANContainsOverrideOperator_EdiPartyName() throws Exception {

        final EdiPartyName ediPartyName = new EdiPartyName();
        ediPartyName.setNameAssigner("?");
        ediPartyName.setPartyName("?");

        final SubjectAltName subjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.EDI_PARTY_NAME, ediPartyName);
        final Entity entity = setUPData.getEntity(null, subjectAltName);

        entityHelper.isSANContainsOverrideOperator(entity);

    }

    /**
     * Test Case for verifying OtherName contains override operator.
     * 
     * @throws Exception
     */

    @Test
    public void testIsSANContainsOverrideOperator_OtherName() throws Exception {

        final OtherName otherName = new OtherName();
        otherName.setTypeId("?");
        otherName.setValue("?");

        final SubjectAltName subjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.OTHER_NAME, otherName);
        final Entity entity = setUPData.getEntity(null, subjectAltName);

        entityHelper.isSANContainsOverrideOperator(entity);

    }

    /**
     * Test Case for verifying SAN fields except EdiPartyName,OtherName contains override operator.
     * 
     * @throws Exception
     */
    @Test
    public void testIsSANContainsOverrideOperator() throws Exception {

        final SubjectAltName subjectAltName = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "?", "dir3", "?");
        final Entity entity = setUPData.getEntity(null, subjectAltName);

        entityHelper.isSANContainsOverrideOperator(entity);

    }

    /**
     * method to test IsSANContainsOverrideOperator with subjectName as null.
     * 
     * @throws Exception
     */
    @Test
    public void testIsSANContainsOverrideOperator_WithSubjectNameNull() throws Exception {

        final Entity entity = setUPData.getEntity(null, null);

        final boolean ExpectedIsSANContainsOverrideOperator = entityHelper.isSANContainsOverrideOperator(entity);

        assertTrue(!ExpectedIsSANContainsOverrideOperator);

    }

    @Test
    public void testValidateECDSAKeyGenAlgorithmWith160KeySize() {

        keySize = 160;
        try {
             entityHelper.validateECDSAKeyGenAlgorithm(ECDSAkeyGeneAlgorithm, keySize);
        } catch (KeyPairGenerationException keyPairGenerationException) {
            assertEquals(ErrorMessages.ECDSA_KEY_SIZE_NOT_SUPPORTED + keySize, keyPairGenerationException.getMessage());
        }
    }

    @Test
    public void testValidateECDSAKeyGenAlgorithmWith163KeySize() {

        keySize = 163;

        try {
            entityHelper.validateECDSAKeyGenAlgorithm(ECDSAkeyGeneAlgorithm, keySize);
        } catch (KeyPairGenerationException keyPairGenerationException) {
            assertEquals(ErrorMessages.ECDSA_KEY_SIZE_NOT_SUPPORTED + keySize, keyPairGenerationException.getMessage());
        }
    }

    @Test
    public void testValidateECDSAKeyGenAlgorithmWith512KeySize() {

        keySize = 512;

        try {
            entityHelper.validateECDSAKeyGenAlgorithm(ECDSAkeyGeneAlgorithm, keySize);
        } catch (KeyPairGenerationException keyPairGenerationException) {
            assertEquals(ErrorMessages.ECDSA_KEY_SIZE_NOT_SUPPORTED + keySize, keyPairGenerationException.getMessage());
        }
    }

    private void mockPKCS10Request(final Entity entity, final KeyPair keyPair) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException {

        final Algorithm signatureAlgorithm = entity.getEntityProfile().getCertificateProfile().getSignatureAlgorithm();
        final String subjectDN = entity.getEntityInfo().getSubject().toASN1String();

        final X500Name name = new X500Name("CN=Test");
        final PKCS10CertificationRequest pKCS10CertificationRequest = pKCS10CertificationRequestSetUP.generatePKCS10Request(name, null);

        Mockito.when(cSRBuilder.generatePKCS10Request(new X500Name(subjectDN), keyPair, signatureAlgorithm.getName(), null)).thenReturn(pKCS10CertificationRequest);
    }

    private CertificateRequest getCertificateRequest(final PKCS10CertificationRequest pKCS10CertificationRequest) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException {

        final CertificateRequest certificateRequest = new CertificateRequest();
        final PKCS10CertificationRequestHolder pkcs10RequestHolder = new PKCS10CertificationRequestHolder(pKCS10CertificationRequest);
        certificateRequest.setCertificateRequestHolder(pkcs10RequestHolder);
        return certificateRequest;
    }
}
