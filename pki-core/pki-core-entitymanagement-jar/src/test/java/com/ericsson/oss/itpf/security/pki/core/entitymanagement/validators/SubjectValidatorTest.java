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

import static org.junit.Assert.assertSame;

import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SubjectValidatorTest {
    @Spy
    Logger logger = LoggerFactory.getLogger(SubjectValidator.class);

    @InjectMocks
    private SubjectValidator subjectValidator;

    @Mock
    private SubjectAltNameValidator subjectAltNameValidator;

    private EntityInfo entityInfo = null;

    final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        entityInfo = entitiesSetUpData.getEntityInfo();

    }

    /**
     * Method to test SubjectValidator in positive scenario.
     */
    @Test
    public void testValidate_ValidSubject() {
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    @Test
    public void testValidate_ValidSubjectCountry() {
        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COUNTRY_NAME);
        subjectField.setValue("US");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_SubjectInvalidCountry() {
        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COUNTRY_NAME);
        subjectField.setValue("INN");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    @Test
    public void testValidate_ValidSubjectLocality() {
        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.LOCALITY_NAME);
        subjectField.setValue("US");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    @Test
    public void testValidate_ValidSubjectNAME() {
        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.GIVEN_NAME);
        subjectField.setValue("US");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    @Test
    public void testValidate_ValidSubjectSURNAME() {
        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.SURNAME);
        subjectField.setValue("K");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    /**
     * Method to test SubjectValidator in positive scenario.
     */
    @Test
    public void testValidate_ValidSubjectFields() {
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.COMMON_NAME, "CHandra");
        assertSame(true, subjectValidator.validate(entityInfo.getSubject()));
    }

    /**
     * Method to test SubjectValidator in positive scenario.
     */
    @Test
    public void testValidate_emptySubjectFields() {
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.ORGANIZATION, " ");
        subMap.put(SubjectFieldType.ORGANIZATION_UNIT, " ");
        subMap.put(SubjectFieldType.SERIAL_NUMBER, " ");
        subMap.put(SubjectFieldType.DN_QUALIFIER, " ");
        subMap.put(SubjectFieldType.TITLE, " ");
        subMap.put(SubjectFieldType.COUNTRY_NAME, " ");
        subMap.put(SubjectFieldType.STATE, "");
        subMap.put(SubjectFieldType.COMMON_NAME, " ");
        subMap.put(SubjectFieldType.GIVEN_NAME, " ");
        subMap.put(SubjectFieldType.SURNAME, " ");
        subMap.put(SubjectFieldType.STREET_ADDRESS, " ");
        entityInfo.setSubject(entitiesSetUpData.createSubject(subMap));
        assertSame(false, subjectValidator.validate(entityInfo.getSubject()));
    }

    /**
     * Method to test Country as Null in SubjectValidator.
     */
    @Test
    public void testValidate_NullSubjectFields() {
        final Subject subject = new Subject();
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.ORGANIZATION, null);
        subMap.put(SubjectFieldType.ORGANIZATION_UNIT, null);
        subMap.put(SubjectFieldType.SERIAL_NUMBER, null);
        subMap.put(SubjectFieldType.DN_QUALIFIER, null);
        subMap.put(SubjectFieldType.TITLE, null);
        subMap.put(SubjectFieldType.COUNTRY_NAME, null);
        subMap.put(SubjectFieldType.STATE, null);
        subMap.put(SubjectFieldType.COMMON_NAME, null);
        subMap.put(SubjectFieldType.GIVEN_NAME, null);
        subMap.put(SubjectFieldType.SURNAME, null);
        subMap.put(SubjectFieldType.STREET_ADDRESS, null);
        entityInfo.setSubject(entitiesSetUpData.createSubject(subMap));
        subjectValidator.validate(subject);
        assertSame(false, subjectValidator.validate(entityInfo.getSubject()));

    }

    /**
     * Method to test Country as Null in SubjectValidator.
     */
    @Test
    public void testValidate_validSubjectFields() {
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.ORGANIZATION, "?");
        subMap.put(SubjectFieldType.ORGANIZATION_UNIT, "?");
        subMap.put(SubjectFieldType.SERIAL_NUMBER, "?");
        subMap.put(SubjectFieldType.DN_QUALIFIER, "?");
        subMap.put(SubjectFieldType.TITLE, "?");
        subMap.put(SubjectFieldType.COUNTRY_NAME, "?");
        subMap.put(SubjectFieldType.STATE, "?");
        subMap.put(SubjectFieldType.COMMON_NAME, "?");
        subMap.put(SubjectFieldType.GIVEN_NAME, "?");
        subMap.put(SubjectFieldType.SURNAME, "?");
        subMap.put(SubjectFieldType.STREET_ADDRESS, "?");
        entityInfo.setSubject(entitiesSetUpData.createSubject(subMap));
        Assert.assertTrue(subjectValidator.validate(entityInfo.getSubject()));

    }

    /**
     * Method to test Country as Null in SubjectValidator.
     */
    @Test
    public void testValidate_InvalidCountry() {
        final Subject subject = new Subject();
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.COUNTRY_NAME, " INN");
        subjectValidator.validate(subject);

    }

    /**
     * Method to test Invalid GivenName in SubjectValidator.
     */
    @Test
    public void testValidate_InvalidGivenNameLength() {
        final Subject subject = new Subject();
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.GIVEN_NAME, "12345678901234567");
        subjectValidator.validate(subject);
    }

    @Test
    public void testValidate_SubjectFieldValue_QuestionTag() {

        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.COUNTRY_NAME);
        subjectField.setValue("?");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));
    }

    @Test
    public void testValidate_ValidSubjectStreetAddress() {
        Subject subject = new Subject();
        SubjectField subjectField = new SubjectField();
        subjectField.setType(SubjectFieldType.STREET_ADDRESS);
        subjectField.setValue("Crater 1621");
        List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        entityInfo.setSubject(subject);
        Assert.assertSame(true, subjectValidator.validate(entityInfo.getSubject()));

    }

    @Test(expected = IllegalArgumentException.class)
    public void testSubjectFieldValidation_IllegalStreetAddress() {
        String fieldName = SubjectFieldType.STREET_ADDRESS.getName();
        String fieldValue = "TCS, Gachibowli, Hyderabad, 500032, INDIA";
        int maxLength = 40;
        subjectValidator.subjectFieldValidation(fieldName, fieldValue, maxLength);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_EMAIL() {
        List<String> emailEntries = new ArrayList<String>();
        emailEntries.add(null);
        subjectValidator.validateEmailEntries(emailEntries);

    }

}
