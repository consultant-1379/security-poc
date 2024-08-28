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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

/**
 * Common class to declare the constant values
 *
 * @author xpranma
 *
 */

public class Constants {

    public static final String ENABLE = "enable";
    public static final String DISABLE = "disable";
    public static final String TRUE = "TRUE";
    public static final String FALSE = "FALSE";
    public static final String NAME = "name";
    public static final String CATEGORY = "category";
    public static final String MODIFIABLE = "modifiable";
    public static final String NEWNAME = "newname";
    public static final String OLDNAME = "oldname";
    public static final String KEY_SIZE = "keysize";
    public static final String CERTIFICATE = "certificate";
    public static final String ENTITY = "entity";
    public static final String TRUST = "trust";
    public static final String ALL = "all";
    public static final String CA = "ca";
    public static final String EE = "ee";
    public static final String XML_FILE = "xmlfile";
    public static final String CERT_FILE = "filename";
    public static final String PROFILE_NAME = "Profile Name";
    public static final String ID = "Id";
    public static final String ENTITY_NAME = "Entity Name";
    public static final String EXT_CA_NAME = "External CA Name";
    public static final String BULK_SUCCESSFUL_INFO = "Profiles imported successfully";
    public static final String IMPORT_EXT_CERT_SUCCESSFUL_INFO = "An external CA certificate imported successfully";
    public static final String EXPORT_EXT_CERT_SUCCESSFUL_INFO = "An external CA certificate exported successfully";
    public static final String UPDATE_EXT_CERT_SUCCESSFUL_INFO = "An external CA updated successfully";
    public static final String CONFIG_CRL_EXT_CERT_SUCCESSFUL_INFO = "CRL parameters configured on external CA successfully";
    public static final String SUCCESSFUL_INFO = "Profile created successfully";
    public static final String UNSUCCESSFUL_INFO = "Import of Profiles failed";
    public static final String SUCCESSFULLY_DELETED = " successfully deleted ";
    public static final String PROFILE_VALIDITY = "Profile Validity: ";
    public static final String MODIFIABLE_VIEW = "Modifiable: ";
    public static final String NAME_VIEW = "Name: ";
    public static final String IS_ACTIVE = "Is Active: ";
    public static final String SUBJECT = "Subject:";
    public static final String PROFILE_TYPE = "profiletype";
    public static final String ENTITY_TYPE = "entitytype";
    public static final String FORMAT = "format";
    public static final String PASSWORD = "password";
    public static final String REISSUE_TYPE = "reissuetype";
    public static final String RENEW_OPTION = "renew";
    public static final String REKEY_OPTION = "rekey";
    public static final String REVOKE_OPTION = "revoke";
    public static final String LEVEL = "level";
    public static final String MODIFICATION_OPTION = "modification";
    public static final String ALLFIELDS = "allfields";

    public static final String URL = "url";
    public static final String SERIAL_NUMBER = "serialnumber";
    public static final String EMPTY_STRING = "";
    public static final String SPACE_STRING = " ";
    public static final String ALGORITHM_TYPE = "type";
    public static final String ALGORITHM_STATUS = "status";
    public static final String ALGORITHM_NAME = "Algorithm Name";
    public static final String ACTION = "action";
    public static final String ENABLED = "enabled";
    public static final String DISABLED = "disabled";
    public static final String DATE_FORMAT = "yyyy-MM-dd HH:mm:ss";

    public static final String AUTO_UPDATE = "autoupdate";
    public static final String TIMER = "timer";

    public static final String[] IMPORT_FAILURE_HEADER = { "Failure reason" };
    public static final String[] ENTITY_HEADER = { "Entity Name", "Entity Type", "Entity Status" };
    public static final String[] ENTITY_CATEGORY_HEADER = { "Entity Name", "Entity Category", "Modifiable", "Entity Status" };
    public static final String LIST_OF_PROFILES = "Following is the list of profile(s)";
    public static final String LIST_OF_ENTITIES = "Following is the list of Entit(y/ies)";

    public static final int SUCCESS = 0;
    public static final int FAILURE = 1;

    public static final String CATEGORY_CREATED_SUCCESSFULLY = "Category created successfully";
    public static final String CATEGORY_UPDATED_SUCCESSFULLY = "Category updated successfully";
    public static final String CATEGORY_DELETED_SUCCESSFULLY = "Category deleted successfully";
    public static final String CATEGORY_LISTED_SUCCESSFULLY = "Category listed successfully";

    public static final String ENTITY_GOT_UPDATED_SUCCESSFULLY = "Entity updated Successfully";
    public static final String ENTITY_DELETED_SUCCESSFULLY = "Entities deleted Successfully";

    public static final String RENEW_SUCCESSFUL_MESSAGE = "Certificate(s) for CA Entity %s renewed successfully";
    public static final String RENEW_AND_REVOKE_SUCCESSFUL_MESSAGE = "Certificate(s) for CA Entity %s renewed and revoked successfully";
    public static final String REKEY_SUCCESSFUL_MESSAGE = "Certificate(s) for CA Entity %s rekeyed successfully";
    public static final String REKEY_AND_REVOKE_SUCCESSFUL_MESSAGE = "Certificate(s) for CA Entity %s rekeyed and revoked successfully";

    public static final String CA_ENTITY_GOT_UPDATED_SUCCESSFULLY = " CAEntity updated Successfully";
    public static final String PROFILES_GOT_CREATED_SUCCESSFULLY = "Profile created Successfully";
    public static final String PROFILES_UPDATED_SUCCESSFULLY = "Profiles updated successfully";
    public static final String PROFILES_DETETED_SUCCESSFULLY = "Profiles deleted successfully";
    public static final String IMPORT_OF_PROFILES_FAILED = "Import of Profiles failed";
    public static final String IS_SUCCESSFULLY_UPDATED = "is sucessfully updated";
    public static final String ALGORITHMS_UPDATED_SUCCESSFULLY = "Algorithms updated Successfully";
    public static final String NO_ALGORITHM_FOUND_MATCHING_CRITERIA = "No algorithm(s) found matching the criteria";
    public static final String NO_CATEGORY_FOUND_MATCHING_CRITERIA = "No category(s) found matching the criteria";
    public static final String NO_PROFILES_FOUND = "No profiles found to be imported in the file";
    public static final String CERTIFICATE_GENERATED_SUCCESSFULLY = "Generation of certificate(s) successful. Please check the path ";
    public static final String ERROR_MSG_MORE_THAN_ONE_HYPHEN = "More than one '-' is not allowed, Please See Command Syntax";
    public static final String INPUT_FILE_MISSING = "Input xml file is missing";
    public static final String NO_ENTITIES_FOUND_IN_XML = "Entity Information is missing in the XML file";
    public static final String NO_PROFILE_FOUND_IN_XML = "Profile Information is missing in the XML file";
    public static final String NO_PROFILE_FOUND_TO_EXPORT = "No profiles are found to be exported";
    public static final String NO_PROFILE_FOUND_IN_SYSTEM = "No profiles are found in system";
    public static final String NO_ENTITIES_FOUND_IN_SYSTEM = "No entities are found in system";

    public static final String SUCCESS_CRL_GENERATION_WITH_SNO = "CRL generated successfully for %s with certificate serial no(s) %s";
    public static final String SUCCESS_CRL_GENERATION_FOR_MULTIPLE_CA = "CRL generated successfully for the CA(s) %s";
    public static final String FAILURE_CRL_GENERATION = "CRL generation failed for %s";
    public static final String ACTIVE = "ACTIVE";
    public static final String INACTIVE = "INACTIVE";
    public static final String ACTIVE_INACTIVE = "ACTIVEINACTIVE";
    public static final String INVALID = "INVALID";

    public static final char COMMA_DELIMITER = ',';
    public static final char HYPHEN_DELIMITER = '-';
    public static final char DOT_DELIMITER = '.';

    public static final String EQUALS = "=";
    public static final String COMMA = ", ";
    public static final String HYPHEN = " - ";
    public static final String NEXT_LINE = System.getProperty("line.separator");
    public static final String FILE_SEPARATOR = System.getProperty("file.separator");
    public static final String TMP_DIR = System.getProperty("java.io.tmpdir");

    public static final String KEY_SIZE_REGEX = "\\d+((-\\d+)?|(,\\d+)*)";
    public static final String SUPPORTED_DELIMITERS_IN_KEY_SIZE = "[,-]";

    public static final String ERROR_WHILE_DELETING = "Error while deleting";
    public static final String ERROR_WHILE_CREATING = "Error while creating";
    public static final String ERROR_WHILE_UPDATING = "Error while updating";
    public static final String ERROR_WHILE_LISTING = "Error while listing";

    public static final String NO_PROFILE_FOUND_WITH_NAME = "No profile found with name ";

    public static final String ENTITIES_SUCCESSFUL_INFO = "Creation of entities successful";
    public static final String ENTITY_SUCCESSFUL_INFO = "Creation of entity successful";
    public static final String ENTITY_UNSUCCESSFUL_INFO = "Import of Entities failed";
    public static final String NO_ENTITIES_FOUND = "No entities found in the imported in the file";
    public static final String TRY_IMPORT_COMMAND_FOR_THAN_ONE_ENTITY = "Try createbulk for creating more than one entity";

    public static final String CERT_GENERATE_ENTITY_NAME = "entityname";

    // TODO: This Constant is declared for Export Certificate. In future
    // ENTITYNAME should only be used instead of CERT_GENERATE_ENTITY_NAME.
    public static final String ENTITYNAME = "entityname";
    public static final String NOCHAIN = "nochain";
    public static final String NOPOPUP = "nopopup";
    public static final String DER_FORMAT = "DER";
    public static final String JKS_EXTENSION = ".jks";
    public static final String P12_EXTENSION = ".p12";
    public static final String PEM_EXTENSION = ".pem";
    public static final String DER_EXTENSION = ".der";
    public static final String KEYSTORE_ALIAS = "cert";
    public static final String CRL_EXTENSION = ".crl";
    public static final String CSR_EXTENSION = ".csr";

    public static final String ZIP_FILE_EXTENSION = ".zip";

    public static final String CERTIFICATE_STATUS = "status";
    public static final String CERTIFICATE_ACTIVE_STATUS = "active";
    public static final String CERTIFICATE_REVOKED_STATUS = "revoked";
    public static final String CERTIFICATE_EXPIRED_STATUS = "expired";
    public static final String CERTIFICATE_INACTIVE_STATUS = "inactive";
    public static final String DEFAULT_PATH = "/var/tmp/";
    public static final String CERTIFICATE_EXTENSION = ".cer";
    public static final String REPLACE_CHARACTERS = "[\\[\\]]";

    public static final String LIST_OF_GENEARTED_CERTIFICATES = "List of Generated Certificate(s)";
    public static final String LIST_OF_CERTIFICATES = "List of Certificate(s)";
    public static final String TRUSTED_LIST_OF_CERTIFICATES = "Following is the list of certificate(s)";
    public static final String CERTIFICATE_CONTENT_TYPE = "application/Cert";
    public static final String XML_CONTENT_TYPE = "application/xml";
    public static final String JKS_CONTENT_TYPE = "application/octet-stream";
    public static final String P12_CONTENT_TYPE = "application/x-pkcs12";
    public static final String PEM_CONTENT_TYPE = "application/x-pem-file";
    public static final String DER_CONTENT_TYPE = "application/x-x509-ca-cert";

    public static final String JKS_FORMAT = "JKS";
    public static final String P12_FORMAT = "P12";
    public static final String PKCS12_FORMAT = "PKCS12";
    public static final String PEM_FORMAT = "PEM";
    public static final String JCEKS_FORMAT = "JCEKS";

    public static final String CA_REISSUE = "CA";
    public static final String CA_IMMEDIATE_SUB_CAS = "CA_IMMEDIATE_SUB_CAS";
    public static final String CA_ALL_CHILD_CAS = "CA_ALL_CHILD_CAS";
    public static final String TYPE = "type: ";
    public static final String CERT_TYPE = "certtype";
    public static final String REVOCATION_REASON_CODE = "reasoncode";
    public static final String REVOCATION_REASON_TEXT = "reasontext";
    public static final String CANAME = "caname";
    public static final String CA_ENTITY_NAME = "caentityname";
    public static final String CERTIFICATE_SERIAL_NUMBER = "serialno";
    public static final String ISSUER_NAME = "issuername";
    public static final String CERTIFICATE_SERIAL_NO = "serialNo";

    public static final String REVOKED_SUCCESSFULLY = " revoked successfully";
    public static final String SUBJECTDN = "subjectDN";
    public static final String ISSUERDN = "issuerDN";
    public static final String INVALIDITY_DATE = "invaliditydate";
    public static final String INVALIDITY_DATE_REGEX = "(((18|19|20|21|22|23)[0-9]{2}-(0[13578]|1[02])-(0[1-9]|[12][0-9]|3[01]))|((18|19|20|21|22|23)[0-9]{2}-(0[469]|11)-(0[1-9]|[12][0-9]|30))|((18|19|20|21|22|23)[0-9]{2}-(02)-(0[1-9]|1[0-9]|2[0-8]))|((((18|19|20|21|22|23)(04|08|[2468][048]|[13579][26]))|2000)-(02)-29))(\\s)([2][0-3]|[0-1][0-9]|[1-9]):[0-5][0-9]:([0-5][0-9]|[6][0])";

    public static final String CRL_GENERATED_SUCCESSFULLY = "CRL generated successfully";
    public static final String CRL_ID = "Id";
    public static final String CRL_CONTENT_TYPE = "application/CRL";
    public static final String COUNT = "count";
    public static final String LIST_OF_CRLS = "List of CRL(s)";

    public static final String CRL_NUMBER = "crlnumber";
    public static final String CRL_ZIP_FILE_NAME = "CRL(s)";

    public static final String CA_ENTITY = "CA Entity";
    public static final String END_ENTITY = "End Entity";

    public static final String ISSUER = "Issuer Name";

    // TODO: These constants have to be moved to pki-common repository once it
    // is created. Declaring here with reference

    public static final String SUPPORTED_DELIMITERS_IN_CA_NAMES = ", ";

    public static final String REMOVE_UNWANTED_COMMA_REGEX = ",([^,]*)$";

    public static final String REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX = "\\[|\\]";

    // TODO: These constants have to be moved to pki-common repository once it is created. Declaring here with reference

    public static final String CRL_GENERATION_FAILED = "CRL generation failed";

    // TODO: These constants have to be moved to pki-common repository once it
    // is created. Declaring here with reference
    // to TORF-53695
    public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
    public static final String BEGIN_NEW_CERTIFICATE_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String END_NEW_CERTIFICATE_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";

    public static final String CERT_STATUS = "certstatus";

    public static final String IPv4 = "IPv4";
    public static final String IPv6 = "IPv6";
    public static final String COLON_OPERATOR = ": ";
    public static final String LEFT_CURLY_BRACE = "{";
    public static final String RIGHT_CURLY_BRACE = "}";

    public static final String NEW_KEY = "newkey";

    public static final String FORCE = "force";
    public static final String CSR_SUCCESS_MESSAGE = "CSR generated successfully for %s";
    public static final String CSR_ALREADY_EXIST = "CSR already exists for %s";

    public static final String RFC_VALIDATION = "rfcvalidation";
    public static final String CA_REISSUE_TYPE = "careissuetype";
    public static final String CERTIFICATE_IMPORT_SUCCESSFULLY = "Certificate imported successfully.";

    public static final String CHAIN_REQUIRED = "chainrequired";

    public static final String[] CRL_HEADER = { "Error Code", "Error Details" };

}