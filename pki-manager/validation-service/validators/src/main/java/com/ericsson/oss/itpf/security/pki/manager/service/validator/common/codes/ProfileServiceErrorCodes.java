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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes;

/**
 * This class contains error messages.
 *
 */
public class ProfileServiceErrorCodes {

    //common error codes
    public static final String ERR_NOT_FOUND_OR_SUPPORTED = " not found or not supported or of invalid category!";
    public static final String ERR_INVALID_NAME_FORMAT = "Invalid Name Format!";
    public static final String ERR_NO_ENTITY_FOUND = "No entity found ";
    public static final String ERR_NO_PROFILE_FOUND = "No profile found ";
    public static final String NOT_FOUND_WITH_NAME = " not found with Name: ";

    //entity category error codes
    public static final String ERR_NO_ENTITYCATEGORY_FOUND = "No entity category name found in entity profile!";
    public static final String ERR_INVALID_ENTITYCATEGORY_FOUND = "Unable to find given entity category in DB!";

    //Key generation algorithm error codes
    public static final String ERR_REQUIRED_ATLEAST_ONE_KEY_GENERATION_ALGORITHM = "Certificate profile must contain at least one key generation algorithm!";
    public static final String ERR_REQUIRED_KEY_GEN_ALGORITHM = "Key generation Algorithm should be specified!";

    //signature algorithm error codes
    public static final String ERR_REQUIRED_ALGORITHM = "Signature Algorithm should be specified in CRLGeneratioInfo";

    //profile validity
    public static final String ERR_INVALID_PROFILE_VALIDITY = "Profile is no longer valid!";

    //certificate profile error codes
    public static final String ERR_NO_CERTIFICATEEXTENSIONS_FOUND = "No Certificate Extensions found in certificate Profile Name: ";
    public static final String ERR_INVALID_ISSUER_VALUE = "For end entities, issuer must be specified!";
    public static final String ERR_GIVEN_ISSUER = "Given issuer ";
    public static final String ERR_ISSUER_REVOKED_EXPIRED = "has been revoked or expired!";
    public static final String ERR_OCCURED_IN_VALIDATING = " Occured in Validating!";
    public static final String ERR_CA_ENTITY_IS_EXTERNAL = "CA Entity is an External CA, so External CA is not allowed to issue a certificate to the entity";
    public static final String ERR_NOT_FOUND = " not found!";
    public static final String ERR_REQUIRED_VALIDITY = "Validity should be specified!";
    public static final String ERR_INVALID_VALIDITY_FORMAT = "Please provide valid value for validity field!";
    public static final String ERR_INVALID_ISSUER_UNIQUE_IDENTIFIER = "For Certificate version V3, issuer unique identifier must be false!";
    public static final String ERR_GIVEN_KEY_GENERATION_ALGORITHM = "Given key generation algorithm ";
    public static final String ERR_GIVEN_ALGORITHM = "Given signature algorithm ";
    public static final String ERR_INVALID_SKEW_TIME_FORMAT = "Invalid Skew Time ";
    public static final String ERR_INVALID_SUBJECT_CAPABILITIES = "SubjectCapabilties cannot be null. It must have at least one subject!";
    public static final String ERR_INVALID_SUBJECT_FIELD_TYPE = "In SubjectField of SubjectCapabilties, type must be specified!";
    public static final String ERR_INVALID_SUBJECT_FIELD_VALUE = "In SubjectField of SubjectCapabilties, value must not be specified!";
    public static final String ERR_INVALID_SUBJECT_UNIQUE_IDENTIFIER = "For Certificate version V3, subject unique identifier must be true!";
    public static final String ERR_ISSUER_INACTIVE_SOFT_DELETED = " is in-active or soft-deleted";

    //entity profile error codes
    public static final String ERR_NO_KEY_PURPOSE_ID_VALUES_IN_DB = "No Key Purpose ID's are found in certificate Profile Extensions";
    public static final String ERR_NO_SUBJECT_ALT_NAME_VALUES_IN_DB = "No SubjectAltName Values are found in certificate Profile Extensions";
    public static final String ERR_INVALID_SUBJECT_FIELD_VALUES = "Subject field values cannot be null or empty";
    public static final String ERR_NO_TRUSTPROFILE_NAME_FOUND = "No Trust Profile found with Name: ";
    public static final String ERR_NO_PROFILE_FOUND_WITH_ID = "No profile found with ID: ";
    public static final String ERR_REQUIRED_SUBJECT_FOR_CA = "For CA entity, subject or subject fields cannot be null or empty in entity profile";
    public static final String ERR_NO_SUBJECT_OR_SUBJECTALTNAME_PRESENT = "EntityProfile should have either Subject or SubjectAltName valid Fields";
    public static final String ERR_CRITICAL_MUST_BE_TRUE = "critical must be true!";
    public static final String ERR_NOT_PRESENT_IN_PROFILES = " not present in entity profile or certificate profile.";

    //trust profile error codes
    public static final String ERR_NOT_FOUND_OR_INACTIVE = " not found or inactive!";
    public static final String ERR_REQUIRED_ATLEAST_ONE_CA = "Trust profile must contain at least one external or internal CA!";

}
