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
package com.ericsson.oss.itpf.security.pki.manager.common.codes;

/**
 * This class contains error message constants.
 * 
 */
public class ProfileServiceErrorCodes {

    public static final String OCCURED_SIGNATURE_ALGORITHM = "Occured in retrieving Signature Algorithm";
    public static final String OCCURED_KEY_GENERATION_ALGORITHM = "Occured in retrieving Key Generation Algorithm";
    public static final String SUGGESTED_SOLUTION_CONSULT_ERROR_LOGS = "An error occurred while executing the command on the system. Consult the error and command logs for more information.";
    public static final String NULL_POINTER_EXCEPTION = "Mandatory Field values are not provided! ";
    public static final String NO_PROFILE_FOUND = "No profile found ";
    public static final String NO_ENTITY_FOUND = "No entity found ";
    public static final String NO_PROFILE_FOUND_WITH_NAME = "No profile found with Name: ";
    public static final String NO_CERTIFICATEPROFILE_NAME_FOUND = "No Certificate Profile found with Name: ";
    public static final String NO_CERTIFICATEEXTENSIONS_FOUND = "No Certificate Extensions found in certificate Profile Name: ";
    public static final String NO_PROFILE_FOUND_WITH_ID = "No profile found with ID: ";
    public static final String UNEXPECTED_SYSTEM_ERROR = "Unexpected internal system error!";
    public static final String INVALID_ARGUMENTS_PASSED = "Invalid arguments are passed.";
    public static final String VALIDATION_ERRORS_SUGGESTION = "Please refer validation errors";
    public static final String NO_PROFILE_FOUND_WITH_ID_AND_NAME = "No profile found with given id and name: ";
    public static final String NOT_FOUND = " not found!";
    public static final String NOT_FOUND_OR_INACTIVE = " not found or inactive!";
    public static final String INVALID_PROFILE_TYPE = "Invalid Profile Type!";
    public static final String INVALID_ENTITY_TYPE = "Invalid Entity Type!";
    public static final String INVALID_SUBJECT_FIELD = "Invalid Subject Field!";
    public static final String TRUSTPROFILE_IN_USE = "Trust Profile is being used by Entity Profiles: ";
    public static final String ID_OR_NAME_SHOULD_PRESENT = "At least id or name should be specified!";
    public static final String OCCURED_IN_CREATING_PROFILE = " Occured in Creating Profile!";
    public static final String OCCURED_IN_DELETING_PROFILE = " Occured in Deleting Profile!";
    public static final String OCCURED_IN_UPDATING_PROFILE = " Occured in Updating Profile!";
    public static final String OCCURED_IN_RETRIEVING_PROFILE = " Occured in Retrieving Profile!";
    public static final String OCCURED_IN_RETRIEVING_PROFILES = " Occured in Retrieving Profiles!";
    public static final String OCCURED_IN_VALIDATING = " Occured in Validating!";
    public static final String TRANSACTION_INACTIVE = "Transaction InActive!";
    public static final String INVALID_OPERATION = "Invalid Operation!";
    public static final String INVALID_NAME_FORMAT = "Invalid Name Format!";
    public static final String NAME_EXISTS_ALREADY = "Name Exists Already!";
    public static final String PROFILE_EXISTS_ALREADY = "Profile Exists Already!";
    public static final String REQUIRED_ATLEAST_ONE_CA = "Trust profile must contain at least one external or internal CA!";
    public static final String GIVEN_INTERNAL_CA = "Given Internal CA(s) ";
    public static final String GIVEN_EXTERNAL_CA = "Given External CA(s) ";
    public static final String OCCURED_IN_CREATING_ENTITY = " Occured in Creating Entity!";
    public static final String OCCURED_IN_DELETING_ENTITY = " Occured in Deleting Entity!";
    public static final String OCCURED_IN_UPDATING_ENTITY = " Occured in Updating Entity!";
    public static final String OCCURED_IN_RETRIEVING_ENTITY = " Occured in Retrieving Entity!";
    public static final String OCCURED_IN_RETRIEVING_ENTITIES = " Occured in Retrieving Entity!";
    public static final String SUBJECT_SUBJECTALT_CAN_NOT_BE_NULL = "Either Subject or Subject Alt Name should be provided! ";
    public static final String NO_TRUSTPROFILE_NAME_FOUND = "No Trust Profile found with Name: ";
    public static final String NO_ALGORITHM_FOUND = "No Algorithm found with Name & KeySize: ";
    public static final String CERTIFICATE_PROFILE = "Certificate Profile: ";
    public static final String REQUIRED_VERSION = "Version should be specified.. only V3 is allowed!";
    public static final String REQUIRED_ALGORITHM = "Signature Algorithm should be specified!";
    public static final String INVALID_VERSION = "Only V3 is allowed!";
    public static final String ISSUER_REVOKED = "has been revoked!";
    public static final String ISSUER_EXPIRED = "has already expired!";
    public static final String GIVEN_ISSUER = "Given issuer ";
    public static final String GIVEN_CA = "For CA ";
    public static final String GIVEN_ALGORITHM = "Given signature algorithm ";
    public static final String GIVEN_KEY_GENERATION_ALGORITHM = "Given key generation algorithm ";
    public static final String GIVEN_KEY_IDENTIFIER_ALGORITHM = "Given key identifier algorithm ";
    public static final String NOT_FOUND_OR_SUPPORTED = " not found or not supported or of invalid category!";
    public static final String KEY_IDENTIFIER_ALGORITHM_NOT_FOUND_OR_SUPPORTED = " not found or not supported or of invalid category!";
    public static final String REQUIRED_ATLEAST_ONE_KEY_GENERATION_ALGORITHM = "Certificate profile must contain at least one key generation algorithm!";
    public static final String REQUIRED_VALIDITY = "Validity should be specified!";
    public static final String REQUIRED_BASIC_CONSTRAINTS = " basic constraints must be specified!";
    public static final String INVALID_PATHLENGTH = "pathlength should be its issuer's pathlength minus 1!!";
    public static final String AUTHORITY_INFORMATION_ACCESS = "For Authority Information Access ";
    public static final String INVALID_VALUE_CRITICAL = "critical must be false!";
    public static final String INVALID_ACCESS_DESCRIPTION = "If not null, access description list must contain at least one access method!";
    public static final String AUTHORITY_KEY_IDENTIFIER = "For Authority Key Identifier ";
    public static final String INVALID_AUTHORITY_KEY_IDENTIFIER = " issuerSubjectAndSerialNumber and key identifier cannot be given as input!";
    public static final String REQUIRED_SUBJECT_KEY_IDENTIFIER = "subject key identifier is mandatory!";
    public static final String SUBJECT_KEY_IDENTIFIER = "In Subject Key Identifier extension,";
    public static final String CA_INVALID_KEY_USAGE_TYPE = "KeyCertSign,cRLSign key usage types are mandatory!";
    public static final String REQUIRED_KEY_CERT_SIGN = "KeyCertSign keyusage type is mandatory!";
    public static final String REQUIRED_CRL_SIGN = "CRLSign keyusage type is mandatory!";
    public static final String REQUIRED_DIGITAL_SIGNATURE = "DigitalSignature keyusage type is mandatory!";
    public static final String REQUIRED_KEY_USAGE = "KeyUsage is mandatory!";
    public static final String INVALID_KEY_USAGE_TYPE = "If not null, at least 1 key usage type must be specified!";
    public static final String INVALID_KEY_PURPOSE_ID = "If not null, extended key usage must contain at least a Key Purpose ID!";
    public static final String CRL_DISTRIBUTION_POINT = "For CRL Distribution Point ";
    public static final String INVALID_VALIDITY_FORMAT = "Invalid Validity!";
    public static final String INVALID_SKEW_TIME_FORMAT = "Invalid Skew Time Format!";
    public static final String INVALID_DISTRIBUTION_POINT_URL = "Invalid Distribution Point URL given!";
    public static final String INVALID_CA_FLAG = "isCA flag in Basicconstraints must be true! ";
    public static final String INVALID_ISSUER_VALUE = "For end entities, issuer must be specified!";
    public static final String GIVEN_END_ENTITY = "For end entity ";
    public static final String INVALID_ACCESS_LOCATION = "Invalid access location given!";
    public static final String REQUIRED_CERTIFICATE_EXTENSIONS = "certificate extensions must be specified!";
    public static final String INVALID_TIME_FORMAT = "Invalid Time Period!";
    public static final String INVALID_CRITICAL_VALUE = "For AnyExtendedKeyUsage, critical must be true!";
    public static final String ISSUER_REVOKED_EXPIRED = "has been revoked or expired!";
    public static final String INVALID_CA_PATHLENGTH = "pathlength should be less than issuer's pathlength: ";
    public static final String CRITICAL_MUST_BE_FALSE = "critical must be false!";
    public static final String INVALID_SUBJECT_UNIQUE_IDENTIFIER = "For Certificate version V3, subject unique identifier must be true!";
    public static final String INVALID_ISSUER_UNIQUE_IDENTIFIER = "For Certificate version V3, issuer unique identifier must be true!";
    public static final String REQUIRED_AUTHORITY_KEY_IDENTIFIER = "Authority Key Identifier must be specified!";
    public static final String GIVEN_ANY_EXTENDED_KEY_USAGE = "For AnyExtendedKeyUsage, ";
    public static final String GIVEN_KEY_USAGE = "For KeyUsage, ";
    public static final String NOT_REQUIRED_KEY_CERT_SIGN = " KeyCertSign must not be specified!";
    public static final String NOT_REQUIRED_CRL_SIGN = " CRLSign must not be specified!";
    public static final String NOT_REQUIRED_DIGITAL_SIGNATURE = " Digital Signature must not be specified!";
    public static final String INVALID_END_ENTITY_PATHLENGTH = "pathLength must be 0!";
    public static final String INVALID_SUBJECT_ALT_NAME = "If not null, at least 1 supported subject alt name field must be specified in SubjectAltName!";
    public static final String BASIC_CONSTRAINTS = "BasicConstraints extension ";
    public static final String CRITICAL_MUST_BE_TRUE = "critical must be true!";
    public static final String ANY_EXTENDED_KEY_USAGE_PRESENT = "If AnyExtendedKeyUsage present, ";
    public static final String INVALID_CRL_DISTRIBUTION_POINTS = "If not null, at least one CRLDistributionPoint must be specified!";
    public static final String INVALID_DISTRIBUTION_POINT_NAME = "Distribution Point Name must contain either list of full names or name relative to CRL issuer!";
    public static final String INVALID_DISTRIBUTION_POINT = "Either DistributionPointName or CRLIssuer must be specified... both can't be present!";
    public static final String INVALID_CRL_ISSUER = "Given CRL Issuer, not found or not active!";
    public static final String INVALID_NAME_RELATIVE_TO_CRL_ISSUER = "Found invalid or inactive NameRelativeToCRLIssuer!";
    public static final String INVALID_END_ENTITY_FLAG = "isCA flag in Basicconstraints must be false!";
    public static final String INVALID_PROFILE_VALIDITY = "Profile is no longer valid!";
    public static final String NO_ENTITY_FOUND_WITH_ID = "No Entity found with ID:";
    public static final String NO_ENTITY_FOUND_WITH_NAME = "No entity found with name:";
    public static final String NO_ENTITY_FOUND_WITH_ID_AND_NAME = "No profile found with ID and Name:";
    public static final String INVALID_EXTENSIONS_FOUND = "Invalid extension found!";
    public static final String UNSUPPORTED_CERTIFICATE_EXTENSION = "Unsupported certificate extension found!";
    public static final String NO_SUBJECT_OR_SUBJECTALTNAME_PRESENT = "EntityProfile should have either Subject or SubjectAltName valid Fields";
    public static final String REASON_FLAG_PRESENT = "If reason flag present, ";
    public static final String INVALID_DISTRIBUTION_POINT_FIELDS = "If the certificate issuer is also the CRL issuer, then CRLIssuer field must be omitted and distributionPointName must be included!";
    public static final String CERTIFICATEPROFILE_IN_USE = "Certificate Profile is being used by Entity Profiles: ";
    public static final String ENTITYPROFILE_IN_USE = "Entity Profile is being used by some Entities ";
    public static final String OCCURED_IN_CREATING = " occured in Creating ";
    public static final String OCCURED_IN_DELETING = " occured in Deleting ";
    public static final String OCCURED_IN_UPDATING = " occured in Updating ";
    public static final String OCCURED_IN_RETRIEVING = "occured in Retrieving ";
    public static final String NOT_FOUND_WITH_NAME = " not found with Name: ";
    public static final String NOT_FOUND_WITH_ID = " not found with ID: ";
    public static final String NOT_FOUND_WITH_ID_AND_NAME = " not found with ID and Name: ";
    public static final String ENTITY_ALREADY_EXISTS = "Entity already exists.";
    public static final String CAENTITY_IN_USE = "CA Entity is in use ";
    public static final String NOT_PRESENT_IN_PROFILES = " not present in entity profile or certificate profile.";
    public static final String NO_SUBJECT_ALT_NAME_VALUES_IN_DB = "No SubjectAltName Values are found in certificate Profile Extensions";
    public static final String NO_KEY_PURPOSE_ID_VALUES_IN_DB = "No Key Purpose ID's are found in certificate Profile Extensions";
    public static final String KEY_USAGE = "For key usage, ";
    public static final String REQUIRED_CRL_DISTRIBUTION_POINTS = "CRLDistributionPoints is mandatory!";
    public static final String NO_PROFILETYPE_PRESENT = "At least one ProfileType should be selected to export Profiles";
    public static final String NO_ENTITYTYPE_PRESENT = "At least one EntityType should be selected to export Entities";
    public static final String VALIDATION_ERROR = "Error occured in validating";
    public static final String EXPIRED_OTP = "OTP is expired";
    public static final String UNKNOWN_PROFILETYPE = "Unknown Profile Type selected to export Profiles";
    public static final String UNKNOWN_ENTITYTYPE = "Unknown Entity Type selected to export Entities";
    public static final String REQUIRED_AUTHORITY_KEY_IDENTIFIER_TYPE = " type must be specified!";
    public static final String INVALID_SUBJECT_ALT_NAME_FIELD_TYPE = "In SubjectAltNameField, type must be specified!";
    public static final String INVALID_SUBJECT_ALT_NAME_FIELD_VALUE = "In SubjectAltNameField, value must not be specified!";
    public static final String REQUIRED_KEY_IDENTIFIER = " KeyIdentifer cannot be null!";
    public static final String KEY_IDENTIFIER = "In KeyIdentifer of SubjectKeyIdentifier extension, ";
    public static final String REQUIRED_KEY_IDENTIFIER_ALGORITHM = " algorithm must be specified!";
    public static final String REQUIRED_SUBJECT_FOR_CA = "For a Entity Profile associated with a Certificate Authority Profile a Subject DN must be selected";
    public static final String INVALID_SUBJECT_CAPABILITIES = "SubjectCapabilties cannot be null. It must have at least one subject!";
    public static final String INVALID_SUBJECT_FIELD_TYPE = "In SubjectField of SubjectCapabilties, type must be specified!";
    public static final String INVALID_SUBJECT_FIELD_VALUE = "In SubjectField of SubjectCapabilties, value must not be specified!";
    public static final String NO_ENTITYCATEGORY_FOUND = "No entity category name found in entity profile!";
    public static final String ENTITY_CATEGORY = " in entity category!";
    public static final String INVALID_ENTITYCATEGORY_FOUND = "Unable to find given entity category in DB!";
    public static final String NO_ENTITIES_FOUND_WITH_CATEGORY = "No entities found with entity category: ";
    public static final String INTERNAL_ERROR = "Exception occured while processing the request";
    public static final String UNEXPECTED_ERROR = "Unexpected System Error";
    public static final String ACTIVE_ENTITY_CAN_NOT_BE_DELETED = "Unable to delete entity as it is active.";
    public static final String OTP_COUNT_EXCEEDED = "OTP count should not exceed 5";
    public static final String INVALID_OTP_COUNT = "OTP count given is zero or negative";
    public static final String OTP_IS_NULL = "OTP can not be Null";
    public static final String CA_ENTITY_IS_EXTERNAL = "CA Entity is an External CA";
    public static final String HOST_NOT_FOUND = "Host configured is null ";
    public static final String ERROR_IN_GETTING_CA_HIERARCHY = "Unexpected error occured while forming CA hierachies";
    public static final String NO_ROOT_CAS = "No Root CAs found";
    public static final String ERR_INVALID_PROFILE_TYPE = "Invalid Profile Type!";
    public static final String ERR_ISSUER_INACTIVE_SOFT_DELETED = " is in-active or soft-deleted";
    public static final String OCCURED_IN_RETRIEVING_ACTIVE_PROFILES = " Occured in Retrieving Active Profiles!";
    public static final String ERROR_OCCURED_UPDATION_ENTITY = "Error occured during updation of entity {} in pkicore ";
    public static final String ERROR_OCCURED_CREATION_ENTITY = "Error occured during creation of entity {} in pkicore ";
    public static final String ERROR_OCCURED_DELETION_ENTITY = "Error occured during deletion of entity {} in pkicore ";
    public static final String ERROR_OCCURED_REVOCATION_ENTITY = "Entity {} certificate revocation failed due to {} "; 

}
