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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
public class ProfileServiceErrorCodesTest {
    @InjectMocks
    ProfileServiceErrorCodes profileServiceErrorCodes;

    /**
     * This method tests the ProfileServiceErrorCodes values
     */
    @Test
    public void testProfileServiceErrorCodes() {
        Assert.assertEquals(profileServiceErrorCodes.ERR_NOT_FOUND_OR_SUPPORTED, " not found or not supported or of invalid category!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_NAME_FORMAT, "Invalid Name Format!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_ENTITY_FOUND, "No entity found ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_PROFILE_FOUND, "No profile found ");
        Assert.assertEquals(profileServiceErrorCodes.NOT_FOUND_WITH_NAME, " not found with Name: ");

        //entity category error codes
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_ENTITYCATEGORY_FOUND, "No entity category name found in entity profile!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_ENTITYCATEGORY_FOUND, "Unable to find given entity category in DB!");

        //Key generation algorithm error codes
        Assert.assertEquals(profileServiceErrorCodes.ERR_REQUIRED_ATLEAST_ONE_KEY_GENERATION_ALGORITHM,
                "Certificate profile must contain at least one key generation algorithm!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_REQUIRED_KEY_GEN_ALGORITHM, "Key generation Algorithm should be specified!");

        //signature algorithm error codes
        Assert.assertEquals(profileServiceErrorCodes.ERR_REQUIRED_ALGORITHM, "Signature Algorithm should be specified in CRLGeneratioInfo");

        //profile validity
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_PROFILE_VALIDITY, "Profile is no longer valid!");

        //trust profile error codes
        Assert.assertEquals(profileServiceErrorCodes.ERR_NOT_FOUND_OR_INACTIVE, " not found or inactive!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_REQUIRED_ATLEAST_ONE_CA, "Trust profile must contain at least one external or internal CA!");
    }

    /**
     * This method tests the certificate profile error codes values
     */
    @Test
    public void testCertProfileErrorCodes() {
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_CERTIFICATEEXTENSIONS_FOUND,
                "No Certificate Extensions found in certificate Profile Name: ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_ISSUER_VALUE, "For end entities, issuer must be specified!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_GIVEN_ISSUER, "Given issuer ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_ISSUER_REVOKED_EXPIRED, "has been revoked or expired!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_OCCURED_IN_VALIDATING, " Occured in Validating!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_CA_ENTITY_IS_EXTERNAL,
                "CA Entity is an External CA, so External CA is not allowed to issue a certificate to the entity");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NOT_FOUND, " not found!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_REQUIRED_VALIDITY, "Validity should be specified!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_VALIDITY_FORMAT, "Please provide valid value for validity field!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_ISSUER_UNIQUE_IDENTIFIER,
                "For Certificate version V3, issuer unique identifier must be false!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_GIVEN_KEY_GENERATION_ALGORITHM, "Given key generation algorithm ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_GIVEN_ALGORITHM, "Given signature algorithm ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_SKEW_TIME_FORMAT, "Invalid Skew Time ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_SUBJECT_CAPABILITIES,
                "SubjectCapabilties cannot be null. It must have at least one subject!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_SUBJECT_FIELD_TYPE, "In SubjectField of SubjectCapabilties, type must be specified!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_SUBJECT_FIELD_VALUE,
                "In SubjectField of SubjectCapabilties, value must not be specified!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_SUBJECT_UNIQUE_IDENTIFIER,
                "For Certificate version V3, subject unique identifier must be true!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_ISSUER_INACTIVE_SOFT_DELETED, " is in-active or soft-deleted");
    }

    /**
     * This method tests the entity profile error codes values
     */
    @Test
    public void testEntityProfileErrorCodes() {
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_KEY_PURPOSE_ID_VALUES_IN_DB,
                "No Key Purpose ID's are found in certificate Profile Extensions");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_SUBJECT_ALT_NAME_VALUES_IN_DB,
                "No SubjectAltName Values are found in certificate Profile Extensions");
        Assert.assertEquals(profileServiceErrorCodes.ERR_INVALID_SUBJECT_FIELD_VALUES, "Subject field values cannot be null or empty");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_TRUSTPROFILE_NAME_FOUND, "No Trust Profile found with Name: ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_PROFILE_FOUND_WITH_ID, "No profile found with ID: ");
        Assert.assertEquals(profileServiceErrorCodes.ERR_REQUIRED_SUBJECT_FOR_CA,
                "For CA entity, subject or subject fields cannot be null or empty in entity profile");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NO_SUBJECT_OR_SUBJECTALTNAME_PRESENT,
                "EntityProfile should have either Subject or SubjectAltName valid Fields");
        Assert.assertEquals(profileServiceErrorCodes.ERR_CRITICAL_MUST_BE_TRUE, "critical must be true!");
        Assert.assertEquals(profileServiceErrorCodes.ERR_NOT_PRESENT_IN_PROFILES, " not present in entity profile or certificate profile.");
    }
}
