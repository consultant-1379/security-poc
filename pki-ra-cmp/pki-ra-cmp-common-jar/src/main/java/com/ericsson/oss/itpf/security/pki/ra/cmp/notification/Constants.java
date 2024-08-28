/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification;

/**
 * This class contains constants which will be used for common utility files.
 *
 * @author xgvgvgv
 *
 */

public class Constants {

    public static final String INVALID_CERTIFICATE_TYPE = "THE GIVEN CERTIFICATE TYPE IS INVALID. ACCEPTED CERTIFICATE TYPES ARE [OAM, IPSEC]";
    public static final String CERTIFICATE_TYPE_OAM = "oam";
    public static final String CERTIFICATE_TYPE_IPSEC = "ipsec";
    public static final String SENDER_DETAILS = "CN=";
    public static final String COMMA_TOKEN = ",";
    public static final String HYPHEN_TOKEN = "-";
    public static final String EQUAL_TOKEN = "=";
    public static final String NO_ERROR_INFO = "No error information";

    private Constants() {

    }
}
