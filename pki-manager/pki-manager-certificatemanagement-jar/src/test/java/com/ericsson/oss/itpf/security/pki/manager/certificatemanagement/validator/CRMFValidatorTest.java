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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import static com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages.KEY_SIZE_NOT_SUPPORTED;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.*;
import java.util.*;

import javax.xml.datatype.DatatypeConfigurationException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class CRMFValidatorTest {

    @InjectMocks
    CRMFValidator crmfValidator;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    private static SetUPData setUPData;
    private static SubjectSetUPData subjectData;
    private static SubjectAltNameSetUPData subjectAltNameData;
    private static CertificateRequestMessageSetUPData certificateRequestMessageSetUPData;
    private static EntitySetUPData entitySetUPData;

    static final String ENTITY_NAME = "Entity";

    @Before
    public void setup() {

        setUPData = new SetUPData();
        subjectData = new SubjectSetUPData();
        subjectAltNameData = new SubjectAltNameSetUPData();
        entitySetUPData = new EntitySetUPData();
        certificateRequestMessageSetUPData = new CertificateRequestMessageSetUPData();
    }

    /**
     * Method to test validation of subject in CRMF.
     * 
     * @throws Exception
     */
    @Test
    public void testValidate_WithSubject() throws Exception {
        final X500Name x500Name = getSubject();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(x500Name, null);

        final String IssuerCANameInEntity = entitySetUPData.getEntity().getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName();

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, IssuerCANameInEntity, Constants.CA_NAME_PATH)).thenReturn(getCAEntityData("CN=ENMSubCA"));

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, getAttributes())).thenReturn(getAlgorithmData());

        crmfValidator.validate(certificateRequestMessage, entitySetUPData.getEntity());
    }

    /**
     * Method to test validation of issuer in CRMF.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidate_WithInvalidIssuer() throws Exception {

        final X500Name x500Name = getSubject();
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(x500Name, null);

        final String IssuerCANameInEntity = entitySetUPData.getCAEntity().getCertificateAuthority().getName();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, IssuerCANameInEntity, Constants.CA_NAME_PATH)).thenReturn(getCAEntityData("CN=SubCA"));

        crmfValidator.validate(certificateRequestMessage, getEntity());
    }

    /**
     * Method to test validation of issuer,where issuer in the CRMF request is invalid name.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidate_WithInvalidIssuerName() throws Exception {
        final X500Name x500Name = getSubject();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(x500Name, null);
        final String IssuerCANameInEntity = entitySetUPData.getEntity().getEntityProfile().getCertificateProfile().getIssuer().getCertificateAuthority().getName();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, IssuerCANameInEntity, Constants.CA_NAME_PATH)).thenReturn(getCAEntityData("ENMSubCA"));
        crmfValidator.validate(certificateRequestMessage, entitySetUPData.getEntity());
    }

    /**
     * Method to test validation of issuer,where issuer in the CRMF request doesn't matches with the entity's subjectDN
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidate_WithInvalidIssuerNameLength() throws Exception {
        final X500Name x500Name = getSubject();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(x500Name, null);

        final String IssuerCANameInEntity = entitySetUPData.getCAEntity().getCertificateAuthority().getName();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, IssuerCANameInEntity, Constants.CA_NAME_PATH)).thenReturn(getCAEntityData("CN=ENMSubCA,O=TCS"));

        crmfValidator.validate(certificateRequestMessage, getEntity());
    }

    /**
     * Method to test validation of SAN in CSR.
     * 
     * @throws Exception
     */
    @Test
    public void testValidate_WithSAN() throws Exception {

        final X500Name x500Name = getSubject();
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(x500Name, "dir7");

        crmfValidator.validateSubjectAndSAN(certificateRequestMessage);
    }

    /**
     * Method to test validation of CRMF without subject and SAN.
     * 
     * @throws Exception
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidate_WithOut_SubjectAndSAN() throws Exception {
        final X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
        final X500Name x500Name = builder.build();

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(x500Name, null);
        crmfValidator.validateSubjectAndSAN(certificateRequestMessage);
    }

    /**
     * Method to test validation of publickeySize, where keysize matches with the keysize in the DB.
     * 
     * @throws Exception
     */
    @Test
    public void validatePublickeySize_KeySize_Matched() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, OperatorCreationException, IOException {

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(new X500Name("CN=TestCA"), "dir1");

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, getAttributes())).thenReturn(getAlgorithmData());
        crmfValidator.validatePublickeySize(certificateRequestMessage);
    }

    /**
     * Method to test validation of publickeySize, where keysize doesn't matches with the keysize in the DB.
     * 
     * @throws Exception
     */
    @Test
    public void validatePublickeySize_KeySize_Not_Matched() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, OperatorCreationException, IOException {

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(new X500Name("CN=TestCA"), "dir1");

        Mockito.when(persistenceManager.findEntitiesByAttributes(AlgorithmData.class, getAttributes())).thenReturn(getAlgorithmData());

        try {
            crmfValidator.validatePublickeySize(certificateRequestMessage);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException exception) {
            assertTrue(exception.getMessage().contains(KEY_SIZE_NOT_SUPPORTED));
        }
    }

    /**
     * Method to test validation of POP.
     * 
     * @throws Exception
     */
    @Test
    public void validatePOP_valid() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, OperatorCreationException, IOException {

        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(new X500Name("CN=TestCA"), "dir1");
        assertTrue(crmfValidator.validatePOP(certificateRequestMessage));

    }

    /**
     * Method to test CANotFoundException.
     * 
     * @throws InvalidCertificateRequestException
     * @throws CANotFoundException
     * @throws DatatypeConfigurationException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws IOException
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateIssuerName_CANotFoundException() throws InvalidCertificateRequestException, CANotFoundException, DatatypeConfigurationException, NoSuchAlgorithmException,
            OperatorCreationException, IOException {
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(new X500Name("CN=TestCA"), "dir1");

        crmfValidator.validateIssuerName(certificateRequestMessage, getEntity());
    }

    /**
     * Method to test InvalidCertificateRequestException.
     * 
     * @throws InvalidCertificateRequestException
     * @throws CANotFoundException
     * @throws DatatypeConfigurationException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws IOException
     */
    @Test(expected = InvalidCertificateRequestException.class)
    public void testValidateIssuerName_InvalidCertificateRequestException() throws InvalidCertificateRequestException, CANotFoundException, DatatypeConfigurationException, NoSuchAlgorithmException,
            OperatorCreationException, IOException {
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(new X500Name("CN=TestCA"), "dir1");

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, ENTITY_NAME, Constants.CA_NAME_PATH)).thenReturn(setUPData.createCAEntityData(ENTITY_NAME, false));

        crmfValidator.validateIssuerName(certificateRequestMessage, getEntity());
    }

    /**
     * Method to test validateIssuerName.
     * 
     * @throws InvalidCertificateRequestException
     * @throws CANotFoundException
     * @throws DatatypeConfigurationException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws IOException
     */
    @Test
    public void testValidateIssuerName() throws InvalidCertificateRequestException, CANotFoundException, DatatypeConfigurationException, NoSuchAlgorithmException, OperatorCreationException,
            IOException {
        final CertificateRequestMessage certificateRequestMessage = certificateRequestMessageSetUPData.generateCRMFRequest(new X500Name("CN=TestCA"), "dir1");

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, ENTITY_NAME, Constants.CA_NAME_PATH)).thenReturn(setUPData.createCAEntityData(ENTITY_NAME, true));

        crmfValidator.validateIssuerName(certificateRequestMessage, getEntity());

    }

    /**
     * Method to get subject in X500Name form.
     * 
     * @return X500Name of the subject.
     */
    private X500Name getSubject() {
        final X500NameBuilder builder = new X500NameBuilder();
        builder.addRDN(BCStyle.CN, CertificateRequestMessageSetUPData.ROOT_CA);
        final X500Name x500Name = builder.build();
        return x500Name;
    }

    private Entity getEntity() throws DatatypeConfigurationException {

        final Subject subject = subjectData.getSubject("Test", "PKI", "Cyberdyne");
        final SubjectAltName subjectAltNameValues = subjectAltNameData.getSubjectAltName(SubjectAltNameFieldType.DNS_NAME, "dir1", "dir2", "dir3");
        final Entity entity = setUPData.getEntity(subject, subjectAltNameValues);

        return entity;
    }

    private CAEntityData getCAEntityData(final String subjectDN) {
        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.getCertificateAuthorityData().setSubjectDN(subjectDN);
        return caEntityData;

    }

    private Map<String, Object> getAttributes() {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("name", "RSA");
        attributes.put("keySize", 2048);
        return attributes;
    }

    private List<AlgorithmData> getAlgorithmData() {
        final List<AlgorithmData> algorithmData = new ArrayList<AlgorithmData>();
        final AlgorithmData algoData = new AlgorithmData();
        algoData.setKeySize(2048);
        algoData.setName("RSA");
        algoData.setSupported(true);
        algorithmData.add(0, algoData);
        return algorithmData;
    }

}
