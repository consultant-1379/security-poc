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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.util.CommonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SubjectAltNameValidatorTest {
    @Mock
    Logger logger;

    @InjectMocks
    private SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    SubjectValidator subjectValidator;

    private EntityInfo entityInfo = null;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityInfo = entitiesSetUpData.getEntityInfo();

    }

    @Test
    public void testValidate_ValidSubjectAltName_EDI_Party_Name() {

        final EdiPartyName ediPatyName = new EdiPartyName();
        ediPatyName.setNameAssigner("Test");
        ediPatyName.setPartyName("Test");
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameField.setValue(ediPatyName);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InvalidSubjectAltName_EDI_Party_Name() {

        final EdiPartyName ediPatyName = new EdiPartyName();
        ediPatyName.setNameAssigner("");
        ediPatyName.setPartyName("");
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameField.setValue(ediPatyName);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_OtherName() {

        OtherName otherName = new OtherName();
        otherName.setTypeId(null);
        otherName.setValue(null);
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameField.setValue(otherName);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_IPAddress() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("null");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test
    public void testValidate_ValidSubjectAltName_RFC822_NAME() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("xyz@abc.com");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.RFC822_NAME);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test
    public void testValidate_ValidSubjectAltName_UNIFORM_RESOURCE_IDENTIFIER() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("Test");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_UNIFORM_RESOURCE_IDENTIFIER() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(null);

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test
    public void testValidate_ValidSubjectAltName_DIRECTORY_NAME() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("Test");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test
    public void testValidate_ValidSubjectAltNameOTHERNAME() {

        OtherName otherName = new OtherName();
        otherName.setTypeId("123");
        otherName.setValue("Test");
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameField.setValue(otherName);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_ValidSubjectAltNameOTHERNAMENUll() {
        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameField.setValue(null);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_DIRECTORY_NAME() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(null);

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_REGESTERED_ID() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(null);

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.REGESTERED_ID);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test
    public void testValidate_ValidSubjectAltName_DNS_NAME() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("Test");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DNS_NAME);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidate_InValidSubjectAltName_DNS_NAME() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(null);

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.DNS_NAME);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

    }

    @Test
    public void testValidate_ValidSubjectAltName_IP_ADDRESS() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("2001:cdba:0000:0000:0000:0000:3257:9652");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);

        assertTrue(CommonUtil.isValidIpAddress("2001:cdba:0000:0000:0000:0000:3257:9652"));

    }

    @Test
    public void testValidate_ValidSubjectAltName_REGESTERED_ID() {

        SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("1.2.22");

        SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        subjectAltNameField.setType(SubjectAltNameFieldType.REGESTERED_ID);
        subjectAltNameField.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameField);
        assertFalse(ValidationUtils.isNullOrEmpty("1.2.22"));
    }

}
