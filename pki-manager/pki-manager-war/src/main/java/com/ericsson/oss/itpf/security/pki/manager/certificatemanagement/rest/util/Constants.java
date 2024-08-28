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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.rest.util;

/**
 * Class is for representing constants of Excluding fields in certificates list JSON Response.
 */

public class Constants {
    public static final String FETCH_RESPONSE_IGNORED_FIELDS = "keySize";
    public static final String LOAD_RESPONSE_IGNORED_FIELDS = "id,notBefore";
    public static final String CERTIFICATE_ZIP_FILE_NAME = "certificates";
    public static final String CERTIFICATE_ZIP_FILE_EXTENSION = ".tar.gz";
    public static final String CERTIFICATE_SUMMARY_RESPONSE_IGNORED_FIELDS = "notBefore,keySize,type,signatureAlgorithm";

    public static final String FILE_NAME_SEPARATOR = "-";
    public static final String CERTIFICATE_FILE_NAME_PREFIX = "certificate";
    public static final String EMPTY_STRING = "";
    public static final String BEGIN_CERTIFICATE_REQUEST = "-----BEGIN CERTIFICATE REQUEST-----";
    public static final String END_CERTIFICATE_REQUEST = "-----END CERTIFICATE REQUEST-----";
    public static final String BEGIN_NEW_CERTIFICATE_REQUEST = "-----BEGIN NEW CERTIFICATE REQUEST-----";
    public static final String END_NEW_CERTIFICATE_REQUEST = "-----END NEW CERTIFICATE REQUEST-----";
    public static final String LINE_SEPARATOR = System.getProperty("line.separator");
    public static final String WINDOWS_LINE_SEPARATOR = "\r\n";
    public static final String LINUX_LINE_SEPARATOR = "\n";

    public static final String RE_ISSUE_COMPLETED = "Re-Issue completed successfully";
    public static final String ENTITY_REISSUE_PASSPHRASE = "password";
}