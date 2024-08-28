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

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SubjectAltNameValidatorTest {
    @Mock
    Logger logger;

    @InjectMocks
    private SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    SubjectValidator subjectValidator;

    private EntityProfile entityProfile = null;
    private EntityProfileData entityProfileData = null;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        final EntityProfileSetUpData entityProfileSetUpToTest = new EntityProfileSetUpData();
        entityProfileData = entityProfileSetUpToTest.getEntityProfileData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        entityProfile.setSubjectAltNameExtension(entityProfileSetUpToTest.getValidSAN());

    }

    /*
     * Method to test SubjectValidator in positive scenario.
     */

    @Test
    public void testValidate_ValidSubjectAltName() {

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

        Mockito.verify(subjectValidator).subjectFieldValidation("value", "Other_arquillian", 200);

    }

    @Test
    public void testValidate_ValidSubjectAltNameWithAllCharacters() {

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyz+.DEFGHI^&*()_|-={}<:>/ABCJKLMNOPQRSTUVWXYZ123456789");
        subjectAltNameValue.setValue(subjectAltNameString);
        subjectAltNameValidator.validate(subjectAltNameValue);
        Mockito.verify(subjectValidator).subjectFieldValidation("dnsName", "abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyz+.DEFGHI^&*()_|-={}<:>/ABCJKLMNOPQRSTUVWXYZ123456789", 255);

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyDirectoryName() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InvalidRegisterID() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }
    /**
    *
    * Method to test SubjectAltNameValidator field DIRECTORY_NAME positive scenario.
    */

   @Test
   public void testValidateDirectoryName() {
       final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
       subjectAltNameValue.setType(SubjectAltNameFieldType.DIRECTORY_NAME);
       final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
       subjectAltNameString.setValue("CN=ERIC");
       subjectAltNameValue.setValue(subjectAltNameString);
       subjectAltNameValidator.validate(subjectAltNameValue);

   }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyOtherName() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyRFC822Name() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InvalidRFC822Name() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyIPaddress() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"abc\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InvalidIPaddress() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"abc\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyDNSName() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"abc\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyRegisterID() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"abc\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyEDIPartyName() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"abc\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandra\",\"partyName\":\"tcs\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario.
     */

    @SuppressWarnings("finally")
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_emptyUniformResourceID() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"DN = aklsjd\"}}"
                        + ",{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"12.2.2.2\",\"value\":\"askld\"}}"
                        + ",{\"type\":\"RFC822_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"abc\"}}"
                        + ",{\"type\":\"IP_ADDRESS\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"172.16.70.90\"}}"
                        + ",{\"type\":\"DNS_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"ericsson\"}}"
                        + ",{\"type\":\"REGESTERED_ID\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"2.5.4.4\"}}"
                        + ",{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"\",\"partyName\":\"\"}}"
                        + ",{\"type\":\"UNIFORM_RESOURCE_IDENTIFIER\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"1234\"}}" + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }

    }

    /**
     * Method to test SubjectAltNameValidator field EdiPartyName in Negative scenario.
     */

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InvalidEdiPartyName() {

        final EdiPartyName ediPatyName = new EdiPartyName();
        ediPatyName.setNameAssigner("");
        ediPatyName.setPartyName("");

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameValue.setValue(ediPatyName);

        subjectAltNameValidator.validate(subjectAltNameValue);

    }

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_NullEdiPartyName() {

        final EdiPartyName ediPatyName = null;

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        subjectAltNameValue.setValue(ediPatyName);

        subjectAltNameValidator.validate(subjectAltNameValue);

    }

    /**
     * Method to test SubjectAltNameValidator field Other Name in Negative scenario.
     */

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InvalidOtherName() {
        final OtherName otherName = new OtherName();
        otherName.setTypeId(null);
        otherName.setValue(null);
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameValue.setValue(otherName);

        subjectAltNameValidator.validate(subjectAltNameValue);

    }

    /**
     * Method to test SubjectAltNameValidator field Other Name in Negative scenario.
     */

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_NullOtherName() {
        final OtherName otherName = null;
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.OTHER_NAME);
        subjectAltNameValue.setValue(otherName);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field Other Name in Negative scenario.
     */

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InvalidIPAddress() {
        final OtherName otherName = null;
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameValue.setValue(otherName);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field IP_ADDRESS in Positive scenario.
     */

    @Test
    public void testValidate_ValidIPAddress() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.IP_ADDRESS);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("127.0.0.1");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field IP_ADDRESS in Negative scenario.
     */

    @Test
    public void testValidate_InValidIPAddress() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.IP_ADDRESS);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("?");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field IP_ADDRESS in Negative scenario.
     */

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InValidIPAddressNull() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.IP_ADDRESS);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     *
     * Method to test SubjectAltNameValidator field IP_ADDRESS in Negative scenario.
     */

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidate_InValidIPAddressValue() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.IP_ADDRESS);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("eric");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);

    }

    /**
     *
     * Method to test SubjectAltNameValidator field RFC822_NAME in Negative scenario.
     */

    @Test
    public void testValidateEmailEntries() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.RFC822_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("?");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);

    }
    /**
    *
    * Method to test SubjectAltNameValidator field RFC822_NAME in Positive scenario.
    */

   @Test
   public void testValidateEmailEntriesWithValue() {
       final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
       subjectAltNameValue.setType(SubjectAltNameFieldType.RFC822_NAME);
       final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
       subjectAltNameString.setValue("ericsson@enm.com");
       subjectAltNameValue.setValue(subjectAltNameString);

       subjectAltNameValidator.validate(subjectAltNameValue);

   }

    /**
     *
     * Method to test SubjectAltNameValidator field UNIFORM_RESOURCE_IDENTIFIER in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateUniformResourceIdsEmpty() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateUniformResourceIdsWithInvalidURI() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("12345");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     *
     * Method to test SubjectAltNameValidator field UNIFORM_RESOURCE_IDENTIFIER in positive scenario.
     */
    @Test
    public void testValidateUniformResourceIdsWithLDAP() {
        String sanUri = "ldap://home/someuser/somefile.txt";
    	final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(sanUri);
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }
    @Test
    public void testValidateUniformResourceIdsWithHTTP() {
    	String sanUri = "http://home/someuser/somefile.txt";
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(sanUri);
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    @Test
    public void testValidateUniformResourceIdsWithFile() {
    	String sanUri = "file://home/someuser/somefile.txt";
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(sanUri);
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }


    /**
     *
     * Method to test SubjectAltNameValidator field EDI_PARTY_NAME in negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateEdiPartyNamesAsNull() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"\"}}"
                        + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }
    }

    /**
     *
     * Method to test SubjectAltNameValidator field EDI_PARTY_NAME in postive scenario.
     */
    @Test
    public void testValidateEdiPartyNames() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"EDI_PARTY_NAME\",\"value\":{\"@class\":\".EdiPartyName\",\"nameAssigner\":\"chandu\",\"partyName\":\"tcs\"}}"
                        + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }
    }

    /**
     *
     * Method to test SubjectAltNameValidator field DNS_NAME in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateDnsNamesAsEmpty() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     *
     * Method to test SubjectAltNameValidator field DNS_NAME in Positive scenario.
     */
    @Test
    public void testValidateDnsNames() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("client2.dev");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario, verify subjectAltName does not contain all digit.
     * 
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateDnsNamesInvalid() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("111.111");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario, verify subjectAltName does not contain space.
     * 
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateDnsNames_InvalidWithSpace() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("ENM TCS");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario, verify that in subjectAltName each label size does not exceed 63 characters.
     * 
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateDnsNames_InvalidLabelLength() {

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyzABCDEFGHI^&*()_+-={}|:<>?/,JKLMNOPQRSTUVWXYZ123456789.com");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator in Negative scenario, verify subjectAltName size does not exceed 255 characters.
     * 
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateDnsNames_InvalidDomainLength() {

        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(
                "abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyzABCDEFGHI^&*()_+-={}|:<.abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyzABCDEFGHI^&*()_+-={}|:<.abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyzABCDEFGHI^&*()_+-={}|:<.abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyzABCDEFGHI^&*()_+-={}|:<.abcdefghi~`!@#$%[]\\;'jklmnopqrstuvwxyzABCDEFGHI^&*()_+-={}|:<");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);

    }

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateDnsNameAsEmpty() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.DNS_NAME);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field REGESTERED_ID in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateRegisterIdsAsNull() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.REGESTERED_ID);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field REGESTERED_ID in Positive scenario.
     */
    @Test
    public void testValidateRegisterId() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.REGESTERED_ID);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("1.2.3.4.5");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field REGESTERED_ID in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testInValidateRegisterId() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.REGESTERED_ID);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("6.3.4");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field REGESTERED_ID in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateRegisterIdValueAsOne() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.REGESTERED_ID);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("2");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field REGESTERED_ID in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateRegisterIdValueAsWrong() {
        final SubjectAltNameField subjectAltNameValue = new SubjectAltNameField();
        subjectAltNameValue.setType(SubjectAltNameFieldType.REGESTERED_ID);
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue("1.2.?");
        subjectAltNameValue.setValue(subjectAltNameString);

        subjectAltNameValidator.validate(subjectAltNameValue);
    }

    /**
     * Method to test SubjectAltNameValidator field OTHER_NAME in Negative scenario.
     */
    @Test(expected = InvalidSubjectAltNameExtension.class)
    public void testValidateOtherNamesAsNull() {
        entityProfileData
                .setSubjectAltName("{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"OTHER_NAME\",\"value\":{\"@class\":\".OtherName\",\"typeId\":\"\",\"value\":\"\"}}"
                        + "]}");

        entityProfile.setSubjectAltNameExtension(JsonUtil.getObjectFromJson(SubjectAltName.class, entityProfileData.getSubjectAltName()));

        final List<SubjectAltNameField> entitySubjectAltNameFieldsList = entityProfile.getSubjectAltNameExtension().getSubjectAltNameFields();
        for (final SubjectAltNameField subjectAltNameFields : entitySubjectAltNameFieldsList) {
            subjectAltNameValidator.validate(subjectAltNameFields);
        }
    }
}
