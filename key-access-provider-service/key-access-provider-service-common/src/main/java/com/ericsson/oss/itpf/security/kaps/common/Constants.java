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

package com.ericsson.oss.itpf.security.kaps.common;

/**
 * All the constants required are defined in the class.
 */
public final class Constants {

    public static final String WRAP_UNWRAP_PRIVATE_KEY_ALGORITHM = "AES/ECB/PKCS5Padding";
    public static final String SHA_256 = "SHA-256";
    public static final String SHA_512 = "SHA-512";
    public static final String SYMMETRIC_KEY_ALGORITHM = "AES";
    public static final String PROVIDER_NAME = "BC";
    public static final String SUBJECT_UNIQUE_IDENTIFIER = "nmsadm";

    private Constants() {}
}
