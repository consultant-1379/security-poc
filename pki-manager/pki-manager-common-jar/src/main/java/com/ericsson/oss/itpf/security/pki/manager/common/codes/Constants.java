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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This class contains constants which will be used for common utility files.
 * 
 * @author xbensar
 * 
 */
public class Constants {

    public static final String OVERRIDE_OPERATOR = "?";
    public static final String COLON_OPERATOR = ":";

    public final static String FILE_SEPARATOR = System.getProperty("file.separator");
    public final static String TMP_DIR = System.getProperty("java.io.tmpdir");
    public static final String NEXT_LINE = System.getProperty("line.separator");

    public static final String JKS_EXTENSION = ".jks";
    public static final String P12_EXTENSION = ".p12";

    public static final String PROVIDER_NAME = BouncyCastleProvider.PROVIDER_NAME;
    public static final String CA_NAME_PATH = "certificateAuthorityData.name";
    public static final String ENTITY_NAME_PATH = "entityInfoData.name";

    public static final int OTP_DEFAULT_COUNT = 5;
    public static final String EMPTY_STRING = "";

    public static final String ERR_MODIFIABLE_PROFILE_FLAG = "Profile modifiable flag is disabled!!";

    /* These ports are configured in PKIRASERVICE group standalone-enm.xml file as part of haproxysb changes */
    public static final String SCEP_PORT = "8090";
    public static final String CMP_PORT = "8091";
    public static final String CDPS_PORT = "8092";
    public static final String TDPS_PORT = "8093";

    public static final String ECDSA_ALGORITHM_NAME = "ECDSA";
    public static final String RSA_ALGORITHM_NAME = "RSA";
    public static final String EC_ALGORITHM_NAME = "EC";
    public static final String digestAlgorithm = "SHA-256";

    public static final String CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE = "Certificate for CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.";
    public static final String ENTITY_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE = "Certificate for End Entity: {entityName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.";
    public static final String EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE = "Certificate for External CA Entity: {caName} With SubjectDN {subjectDN} and Serial Number {serialNumber} will expire in {numberOfDays} DAYS.Contact External Certificate Authority to get the CA certificate reissued.";
    public static final String DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL = "P30D";
    public static final String DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL = "P1D";
    public static final String DEFAULT_PERIOD_BEFORE_EXPIRY_MAJOR = "P60D";
    public static final String DEFAULT_FREQUENCY_OF_NOTIFICATION_MAJOR = "P2D";
    public static final String DEFAULT_PERIOD_BEFORE_EXPIRY_WARNING = "P90D";
    public static final String DEFAULT_FREQUENCY_OF_NOTIFICATION_WARNING = "P4D";
    public static final String DEFAULT_PERIOD_BEFORE_EXPIRY_MINOR = "P180D";
    public static final String DEFAULT_FREQUENCY_OF_NOTIFICATION_MINOR = "P7D";
    public static final String UNSUPPORTED_CHAR_REGEX = ".*[=,/\"\\\\].*";
    public static final String UNSUPPORTED_DIRECTORY_STRING_REGEX = ".*[=/\"\\\\].*";
    public static final String UNSUPPORTED_SUID_CHAR_REGEX = ".*[?=,/\"\\\\].*";
    public static final String DEFAULT_SUBJECT_UNIQUE_IDENTIFIER_VALUE = "nmsadm";
    public final static boolean INACTIVE_CERTIFICATE_VALID = true;
    public final static boolean INACTIVE_CERTIFICATE_NOT_VALID = false;

    public static final String SECP256R1_OID = "1.2.840.10045.3.1.7";
    public static final String SECP384R1_OID = "1.3.132.0.34";
    public static final String SECP521R1_OID = "1.3.132.0.35";

    public static final List<String> COMMA_SUPPORTED_DN_FIELD_TYPES = Collections.unmodifiableList(Arrays.asList("CN", "SURNAME", "L", "ST", "STREET", "O", "OU", "DN", "T", "GIVENNAME", "SN", "INITIALS", "GENERATION"));
}
