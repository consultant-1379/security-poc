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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators;

/**
 * Test Class for CAValidator.
 */
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.*;

import javax.persistence.PersistenceException;
import javax.xml.datatype.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.IssuingDistributionPoint;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

@RunWith(MockitoJUnitRunner.class)
public class CAValidatorTest {

    @Mock
    final Logger logger = LoggerFactory.getLogger(CAValidator.class);

    @InjectMocks
    CAValidator caEntityValidator;

    @Mock
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    SubjectValidator subjectValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CAValidator caEntityValidatorMock;
    CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
    CrlGenerationInfo crlGenerationInfo = new CrlGenerationInfo();
    final List<CertificateAuthorityData> subCAList = new ArrayList<CertificateAuthorityData>();
    final List<CrlGenerationInfo> crlGenerationInfos = new ArrayList<CrlGenerationInfo>();
    private static final String OVERRIDING_OPERATOR = "?";
    private static final String LOGGER_VALIDATE_CAENTITY = "Completed validating {} Certificate Authroity ";
    private static Duration duration;

    private static CertificateAuthority certificateAuthority;

    /**
     * Prepares initial Data.
     */
    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        certificateAuthority = entitiesSetUpData.getCertificateAuthority();

        certificateAuthorityData = entitiesSetUpData.getCertificateAuthorityData();
    }

    /**
     * Method to test validateCreate.
     */
    @Test
    public void testValidateCreate() {

        caEntityValidator.validateCreate(certificateAuthority);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidateCreateWithInvalidName() {

        certificateAuthority.setName("ENM RootCA");

        caEntityValidator.validateCreate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidateCreateWithInvalidName1() {

        certificateAuthority.setName("ENMSu&%bCA");

        caEntityValidator.validateCreate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of EntityAlreadyExistsException.
     * 
     * @return EntityAlreadyExistsException.
     */
    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testCreateNameAlreadyExisting() {

        certificateAuthority.setName("ENMSubCA");

        when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENMSubCA", EntitiesSetUpData.NAME_PATH)).thenReturn(certificateAuthorityData);

        caEntityValidator.validateCreate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateNameNull() {
        certificateAuthority.setSubjectAltName(null);
        certificateAuthority.setName(null);

        caEntityValidator.validateCreate(certificateAuthority);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateEmptySubject() {
        certificateAuthority.setSubjectAltName(null);
        certificateAuthority.setName("");

        caEntityValidator.validateCreate(certificateAuthority);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testcertificateAuthorityNull() {
        caEntityValidator.validateCreate(null);

    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test
    public void testValidateUpdate() {

        when(persistenceManager.findEntity(CertificateAuthorityData.class, 1)).thenReturn(certificateAuthorityData);

        caEntityValidator.validateUpdate(certificateAuthority);

        verify(persistenceManager, times(2)).findEntity(CertificateAuthorityData.class, 1);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNoSubjectAndSAN() {

        certificateAuthority.setSubject(null);

        caEntityValidator.validateCreate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testNullSubjectValue() {

        final HashMap<SubjectFieldType, String> subjectDN = new HashMap<SubjectFieldType, String>();
        final Subject subject = new Subject();
        subjectDN.put(SubjectFieldType.COMMON_NAME, OVERRIDING_OPERATOR);
        subject.setSubjectFields(null);

        certificateAuthority.setSubject(subject);

        caEntityValidator.validateCreate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testSubjectValue() {

        final HashMap<SubjectFieldType, String> subjectDN = new HashMap<SubjectFieldType, String>();
        final Subject subject = new Subject();
        subjectDN.put(SubjectFieldType.COMMON_NAME, OVERRIDING_OPERATOR);
        subject.setSubjectFields(null);

        certificateAuthority.setSubject(subject);

        caEntityValidator.validateCreate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of EntityNotFoundException.
     * 
     * @return EntityNotFoundException.
     */
    @Test(expected = CoreEntityNotFoundException.class)
    public void testUpdateNotExistingEntity() {

        certificateAuthority.setName("ENMSubCA");

        when(persistenceManager.findEntity(CertificateAuthorityData.class, 1)).thenReturn(null);

        caEntityValidator.validateUpdate(certificateAuthority);

    }

    /**
     * Method to test validateUpdate.
     */
    @Test
    public void testUpdateNameEx() {

        certificateAuthority.setName("ENMSubCA");

        when(persistenceManager.findEntity(CertificateAuthorityData.class, 1)).thenReturn(certificateAuthorityData);

        caEntityValidator.validateUpdate(certificateAuthority);

    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testValidateUpdate_IllegalArgumentException() {

        when(persistenceManager.findEntity(CertificateAuthorityData.class, 1)).thenReturn(certificateAuthorityData);

        certificateAuthority.setSubject(null);
        certificateAuthority.setSubjectAltName(null);
        caEntityValidator.validateUpdate(certificateAuthority);

    }

    /**
     * Method to test checkNameAvailability.
     */
    @Test
    public void testCheckNameAvailability() {

        when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENMCA", EntitiesSetUpData.NAME)).thenReturn(null);

        caEntityValidator.checkNameAvailability("ENMCA", CertificateAuthorityData.class, EntitiesSetUpData.NAME);

    }

    /**
     * Method to test Occurrence of EntityServiceException.
     * 
     * @return EntityServiceException.
     */

    @Test(expected = CoreEntityServiceException.class)
    public void testCheckNameAvailabilityEx() {

        when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENMCA", EntitiesSetUpData.NAME)).thenThrow(new PersistenceException());

        caEntityValidator.checkNameAvailability("ENMCA", CertificateAuthorityData.class, EntitiesSetUpData.NAME);

    }

    /**
     * Method to test Occurrence of EntityAlreadyExistsException.
     * 
     * @return EntityAlreadyExistsException.
     */
    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testCheckNameAvailabilityEntityAlreadyExistsException() {

        when(persistenceManager.findEntityByName(CertificateAuthorityData.class, "ENMCA", EntitiesSetUpData.NAME)).thenReturn(certificateAuthorityData);

        caEntityValidator.checkNameAvailability("ENMCA", CertificateAuthorityData.class, EntitiesSetUpData.NAME);

    }

    /**
     * Method to test Occurrence of AlgorithmValidationException.
     * 
     * @return AlgorithmValidationException.
     */
    @Ignore
    @Test(expected = AlgorithmValidationException.class)
    public void testCreateValidateCAEntityWhenCrlExtensionNull_IllegalArgumentException() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("crlException"));

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateValidateCAEntity_IllegalArgumentException() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("Exception"));

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test Occurrence of AlgorithmValidationException.
     * 
     * @return AlgorithmValidationException.
     */
    @Ignore
    @Test(expected = AlgorithmValidationException.class)
    public void testCreateValidateCAEntity_AlgorithmValidationException() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("ValidityException"));

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test Occurrence of AlgorithmValidationException.
     * 
     * @return AlgorithmValidationException.
     */
    @Ignore
    @Test(expected = AlgorithmValidationException.class)
    public void testCreateValidateCAEntityWhenalgorithmDataFromDBIsNull_AlgorithmValidationException() {
        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("Success"));
        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test validateCAEntity.
     */
    @Test
    public void testCreateValidateCAEntity() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("Success"));
        certificateAuthority.getCrlGenerationInfo().get(0).setSignatureAlgorithm(null);

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test Occurrence of AlgorithmValidationException.
     * 
     * @return AlgorithmValidationException.
     */
    @Ignore
    @Test(expected = AlgorithmValidationException.class)
    public void testCreateValidateCAEntityWhenAuthorityInformationAccessIsNull_IllegalArgumentException() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("Success"));
        certificateAuthority.getCrlGenerationInfo().get(0).getCrlExtensions().setAuthorityInformationAccess(null);

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test validateCAEntity
     */
    @Test
    public void testUpdateValidate() {

        certificateAuthority.setName("ENMSubCA");

        when(persistenceManager.findEntity(CertificateAuthorityData.class, 1)).thenReturn(certificateAuthorityData);
        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.UPDATE);

        verify(persistenceManager, times(1)).findEntity(CertificateAuthorityData.class, 1);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateValidateCAEntityWhenSubjectFieldValueEqualsToOverridingOperator() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("crlException"));

        certificateAuthority.getSubject().getSubjectFields().get(0).setValue(OVERRIDING_OPERATOR);

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateValidateCAEntityWhenSubjectFieldValueIsEmpty() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("crlException"));

        certificateAuthority.getSubject().getSubjectFields().get(0).setValue(new String());

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test CreateValidateCAEntityWhenSubjectAlternateNameIsEmpty.
     * 
     */
    @Test
    public void testCreateValidateCAEntityWhenSubjectAlternateNameIsEmpty2() {

        List<SubjectAltNameField> subjectAltNameFieldsList = new LinkedList<SubjectAltNameField>();

        certificateAuthority.getSubjectAltName().setSubjectAltNameFields(subjectAltNameFieldsList);

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);

        Mockito.verify(logger).debug(LOGGER_VALIDATE_CAENTITY, "create");
    }

    /**
     * Method to test Occurrence of IllegalArgumentException.
     * 
     * @return IllegalArgumentException.
     */
    @Test(expected = IllegalArgumentException.class)
    public void testCreateValidateCAEntityWhenValidityPeriodIsNull() {

        certificateAuthority.setCrlGenerationInfo(getCrlGenerationInfoList("Success"));

        certificateAuthority.getCrlGenerationInfo().get(0).setValidityPeriod(null);

        Mockito.when(algorithmPersistenceHandler.getAlgorithmByNameAndType(certificateAuthority.getCrlGenerationInfo().get(0).getSignatureAlgorithm(), AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(
                new AlgorithmData());

        caEntityValidator.validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Method to test Occurrence of EntityInUseException.
     * 
     * 
     */
    @Test(expected = CoreEntityInUseException.class)
    public void testIsCACanBeDeleted_EntityInUseException() {
        caEntityValidator.isCACanBeDeleted(CAStatus.ACTIVE);

    }

    /**
     * Method to test Occurrence of EntityAlreadyDeletedException.
     * 
     * 
     */
    @Test
    public void testIsCACanBeDeleted_EntityAlreadyDeletedException() {
        caEntityValidator.isCACanBeDeleted(CAStatus.DELETED);
    }

    /**
     * Method to test isCACanBeDeleted.
     */
    @Test
    public void testIsCACanBeDeleted() {
        boolean isTrue = caEntityValidator.isCACanBeDeleted(CAStatus.INACTIVE);
        assertNotNull(isTrue);
        assertEquals(true, isTrue);

    }

    /**
     * Method to test checkCAEntityHasEntities.
     */
    @Test
    public void getCheckCAEntityHasEntities() {
        caEntityValidator.checkCAEntityHasEntities(OVERRIDING_OPERATOR);

        verify(caEntityPersistenceHandler).getSubCAsUnderCA(OVERRIDING_OPERATOR);
    }

    /**
     * Method to test checkSubCAsUnderCA.
     */
    @Test
    public void getCheckSubCAsUnderCA() {
        List<CertificateAuthorityData> subCAList = new ArrayList<CertificateAuthorityData>();
        subCAList.add(certificateAuthorityData);

        caEntityValidator.checkSubCAsUnderCA(subCAList);
        caEntityValidatorMock.checkSubCAsUnderCA(subCAList);
        Mockito.verify(caEntityValidatorMock).checkSubCAsUnderCA(subCAList);

    }

    /**
     * Method to test Occurrence of EntityInUseException.
     * 
     * @return EntityInUseException.
     */
    @Test(expected = CoreEntityInUseException.class)
    public void getCheckSubCAsUnderCA_EntityInUseException() {

        List<CertificateAuthorityData> subCAList = new ArrayList<CertificateAuthorityData>();
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        subCAList.add(certificateAuthorityData);

        caEntityValidator.checkSubCAsUnderCA(subCAList);
    }

    /**
     * Method to test whether the passing String is null/empty or not.
     * 
     */
    @Test
    public void testIsNullOrEmptyPassingStringLiteral() {

        assertFalse(CAValidator.isNullOrEmpty(OVERRIDING_OPERATOR));
    }

    /**
     * Method to test whether the passing String is null or Empty.
     * 
     */
    @Test
    public void testIsNullOrEmptyPassingEmptyString() {

        assertTrue(CAValidator.isNullOrEmpty(new String()));
    }

    /**
     * Method testisValidSubjectString() used for checking if String is having ?
     * 
     */

    @Test
    public void testIsValidSubjectString() {

        assertTrue(CAValidator.isValidSubjectString(OVERRIDING_OPERATOR));
    }

    /**
     * Method testIsValidSubjectStringPassingEmptyString() used for checking if String is having ?
     * 
     */

    @Test
    public void testIsValidSubjectStringPassingEmptyString() {

        assertFalse(CAValidator.isValidSubjectString(new String()));
    }

    /**
     * Method testisAsciiPrintable() used for checking if given character is valid ASCII printable character
     * 
     */

    @Test
    public void testIsAsciiPrintable() {

        assertTrue(CAValidator.isAsciiPrintable(OVERRIDING_OPERATOR.charAt(0)));
    }

    /**
     * Method testIsAsciiPrintablePassingInvalidASCIICharacter() used for checking if given character is valid ASCII printable character
     * 
     */

    @Test
    public void testIsAsciiPrintablePassingInvalidASCIICharacter() {

        assertFalse(CAValidator.isAsciiPrintable(new String().concat("₹").charAt(0)));
    }

    /**
     * Method testIsAsciiPrintableWithValidString() used for checking if given String is valid ASCII printable or not.
     * 
     */

    @Test
    public void testIsAsciiPrintableWithValidString() {

        assertTrue(CAValidator.isAsciiPrintable(OVERRIDING_OPERATOR));
    }

    /**
     * Method testIsAsciiPrintableWithInvalidString() used for checking if given String is valid or not.
     * 
     */

    @Test
    public void testIsAsciiPrintableWithInvalidString() {

        assertFalse(CAValidator.isAsciiPrintable(new String().concat("₹")));
    }

    /**
     * Method testgetEntityDataById() used for retrieving the entity data from database
     * 
     */

    @Test
    public void testGetEntityDataById() {

        Mockito.when(persistenceManager.findEntity(CertificateAuthorityData.class, 1)).thenReturn(certificateAuthorityData);
        CertificateAuthorityData actualCertificateAuthorityData = caEntityValidator.getEntityDataById(1, CertificateAuthorityData.class);
        assertNotNull(actualCertificateAuthorityData);
        assertEquals(actualCertificateAuthorityData, certificateAuthorityData);
    }

    /**
     * Method to get List<CrlGenerationInfo>.
     * 
     * @return List<CrlGenerationInfo>.
     */
    public static List<CrlGenerationInfo> getCrlGenerationInfoList(String Exception) {
        List<CrlGenerationInfo> CrlGenerationInfoList = new ArrayList<CrlGenerationInfo>();
        if (Exception == "Exception") {
            CrlGenerationInfoList.add(getCrlGenerationInfo("NotSet", "NotSet", "CrlExtension"));
        } else if (Exception == "ValidityException") {
            CrlGenerationInfoList.add(getCrlGenerationInfo("Set", "NotSet", "CrlExtension"));
        }

        else if (Exception == "crlException") {
            CrlGenerationInfoList.add(getCrlGenerationInfo("Set", "Set", "Exception"));
        } else {
            CrlGenerationInfoList.add(getCrlGenerationInfo("Set", "Set", "CrlExtension"));
        }
        return CrlGenerationInfoList;
    }

    /**
     * Method to get CrlGenerationInfo.
     * 
     * @return CrlGenerationInfo.
     */
    public static CrlGenerationInfo getCrlGenerationInfo(String version, String validity, String crlExtension) {
        try {
            duration = DatatypeFactory.newInstance().newDuration("P42D");
        } catch (DatatypeConfigurationException e) {
            e.printStackTrace();
        }
        ArrayList<Certificate> inActiveCertificates = new ArrayList<Certificate>();
        CrlGenerationInfo CrlGenerationInfo = new CrlGenerationInfo();
        CrlGenerationInfo.setCaCertificates(inActiveCertificates);
        CrlGenerationInfo.setId(123);
        CrlExtensions crlExtensions = new CrlExtensions();
        AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess();
        authorityInformationAccess.setCritical(true);
        crlExtensions.setAuthorityInformationAccess(authorityInformationAccess);
        AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setCritical(true);
        crlExtensions.setAuthorityKeyIdentifier(authorityKeyIdentifier);
        IssuingDistributionPoint issuingDistributionPoint = new IssuingDistributionPoint();
        issuingDistributionPoint.setCritical(true);
        crlExtensions.setIssuingDistributionPoint(issuingDistributionPoint);

        if (version == "Set") {
            CrlGenerationInfo.setVersion(CRLVersion.V2);
        } else {
            CrlGenerationInfo.setVersion(null);
        }
        if (validity == "Set") {
            CrlGenerationInfo.setValidityPeriod(duration);
        } else {
            CrlGenerationInfo.setValidityPeriod(null);
        }
        if (crlExtension == "CrlExtension") {
            CrlGenerationInfo.setCrlExtensions(crlExtensions);
        } else if (crlExtension == "Exception") {
            CrlGenerationInfo.setCrlExtensions(null);
        }
        Algorithm signatureAlgorithm = new Algorithm();
        signatureAlgorithm.setId(1);
        CrlGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        return CrlGenerationInfo;
    }

    @Test
    public void testCheckCAEntityHasEntities() {
        subCAList.add(certificateAuthorityData);
        when(caEntityPersistenceHandler.getSubCAsUnderCA("caEntityName")).thenReturn(subCAList);
        caEntityValidator.checkCAEntityHasEntities("caEntityName");
        verify(caEntityPersistenceHandler, times(1)).checkSubCAsUnderCA(subCAList);
    }

    @Test
    public void testCheckSubCAsUnderCA() {
        certificateAuthorityData.setId(2L);
        certificateAuthorityData.setName("name");
        subCAList.add(certificateAuthorityData);
        when(caEntityPersistenceHandler.getSubCAsUnderCA("caEntityName")).thenReturn(subCAList);
        caEntityValidator.checkSubCAsUnderCA(subCAList);
        verify(caEntityPersistenceHandler, times(1)).getSubCAsUnderCA("name");
    }
}
