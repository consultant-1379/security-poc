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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile;

import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SubjectValidatorTest {
    @Spy
    Logger logger = LoggerFactory.getLogger(SubjectValidator.class);

    @InjectMocks
    private SubjectValidator subjectValidator;

    @Mock
    private SubjectAltNameValidator subjectAltNameValidator;

    private EntityProfile entityProfile = null;

    private final static String INVALID_GIVEN_NAME = "/";
    private final static String INVALID_COMMON_NAME = "PK=I";
    private final static String INVALID_STATE = "PK\\I";
    private final static String INVALID_ORGANIZATION = "PK\"I";
    private final static String INVALID_DC = "xTestDC1,TestDC2";

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        final EntityProfileSetUpData entityProfileSetUpToTest = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();

    }

    /**
     * Method to test SubjectValidator in positive scenario.
     */
    @Test
    public void testValidate_ValidSubject() {

        Assert.assertSame(true, subjectValidator.validate(entityProfile.getSubject()));

    }

    /**
     * Method to test SubjectValidator in positive scenario.
     */
    @Test
    public void testValidate_ValidSubjectFields() {
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.COMMON_NAME, "CHandra");
        // subject.setSubjectDN(subMap);
        Assert.assertSame(true, subjectValidator.validate(entityProfile.getSubject()));
    }

    /**
     * Method to test SubjectValidator in positive scenario.
     */
    @Test
    public void testValidate_emptySubjectFields() {
        final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        subMap.put(SubjectFieldType.ORGANIZATION, "");
        subMap.put(SubjectFieldType.ORGANIZATION_UNIT, " ");
        subMap.put(SubjectFieldType.SERIAL_NUMBER, " ");
        subMap.put(SubjectFieldType.DN_QUALIFIER, " ");
        subMap.put(SubjectFieldType.TITLE, " ");
        subMap.put(SubjectFieldType.COUNTRY_NAME, " ");
        subMap.put(SubjectFieldType.STATE, "");
        subMap.put(SubjectFieldType.COMMON_NAME, " ");
        subMap.put(SubjectFieldType.GIVEN_NAME, " ");
        subMap.put(SubjectFieldType.SURNAME, " ");
        // subject.setSubjectDN(subMap);
        Assert.assertSame(true, subjectValidator.validate(entityProfile.getSubject()));
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
        // subject.setSubjectDN(subMap);
        subjectValidator.validate(subject);
        Assert.assertSame(true, subjectValidator.validate(entityProfile.getSubject()));

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
        // subject.setSubjectDN(subMap);
        Assert.assertSame(true, subjectValidator.validate(entityProfile.getSubject()));

    }

    /**
     * Method to test Country as Null in SubjectValidator.
     */
    @Test(expected = InvalidSubjectException.class)
    public void testValidate_InvalidCountry() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.COUNTRY_NAME);
        subjectField.setValue("I_NN");
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        // final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>();
        // subMap.put(SubjectFieldType.COUNTRY_NAME, "");
        // subject.setSubjectDN(subMap);
        subjectValidator.validate(subject);

    }

    /**
     * Method to test Invalid GivenName in SubjectValidator.
     */
    @Test(expected = InvalidSubjectException.class)
    public void testValidate_InvalidGivenNameLength() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.GIVEN_NAME);
        subjectField.setValue("12345678901234567");
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        /*
         * final Subject subject = new Subject(); final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>(); subMap.put(SubjectFieldType.GIVEN_NAME,
         * "12345678901234567");
         */
        // subject.setSubjectDN(subMap);
        subjectValidator.validate(subject);

    }

    /**
     * Method to test Invalid GivenName in SubjectValidator.
     */
    @Test
    public void testValidate_ValidSubjectString() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.GIVEN_NAME);
        subjectField.setValue("?");
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);

        /*
         * final Subject subject = new Subject(); final HashMap<SubjectFieldType, String> subMap = new HashMap<SubjectFieldType, String>(); subMap.put(SubjectFieldType.GIVEN_NAME,
         * "12345678901234567");
         */
        // subject.setSubjectDN(subMap);
        subjectValidator.validate(subject);

    }

    /**
     * Method to test Valid StreetAddress in SubjectValidator.
     */
    @Test
    public void testValidate_ValidStreetAddress() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.STREET_ADDRESS);
        subjectField.setValue("!");
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        Assert.assertTrue(subjectValidator.validate(subject));

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_SubjectField_UnSupportedChars1_ThrowsInvalidSubjectException() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.GIVEN_NAME);
        subjectField.setValue(INVALID_GIVEN_NAME);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        subjectValidator.validate(subject);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_SubjectField_UnSupportedChars2_ThrowsInvalidSubjectException() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.COMMON_NAME);
        subjectField.setValue(INVALID_COMMON_NAME);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        subjectValidator.validate(subject);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_SubjectField_UnSupportedChars3_ThrowsInvalidSubjectException() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.STATE);
        subjectField.setValue(INVALID_STATE);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        subjectValidator.validate(subject);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_SubjectField_UnSupportedChars4_ThrowsInvalidSubjectException() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.ORGANIZATION);
        subjectField.setValue(INVALID_ORGANIZATION);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        subjectValidator.validate(subject);

    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_Subject_UnSupportedChars_Subject_Field_Type_Comma_Not_Supported_ThrowsInvalidSubjectException() {
        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final Subject subject = new Subject();
        final SubjectField subjectField = new SubjectField();

        subjectField.setType(SubjectFieldType.DC);
        subjectField.setValue(INVALID_DC);
        subjectFields.add(subjectField);
        subject.setSubjectFields(subjectFields);
        subjectValidator.validate(subject);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_EMAIL() {
        List<String> emailEntries = new ArrayList<String>();
        emailEntries.add(null);
        subjectValidator.validateEmailEntries(emailEntries);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_INVALID_EMAIL() {
        List<String> emailEntries = new ArrayList<String>();
        emailEntries.add("ericsson");
        subjectValidator.validateEmailEntries(emailEntries);

    }
}
