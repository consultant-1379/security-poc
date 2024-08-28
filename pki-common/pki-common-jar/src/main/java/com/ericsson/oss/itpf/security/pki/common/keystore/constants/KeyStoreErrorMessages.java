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
package com.ericsson.oss.itpf.security.pki.common.keystore.constants;

/**
 * This class contains all the errorMessages which will be used as the Key Store related exception descriptions.
 * 
 * @author xkarlak
 */

public class KeyStoreErrorMessages {

    public static final String KEY_STORE_LOAD_FAILURE = "Failure in initializing Key Store";
    public static final String READ_PRIVATE_KEY_FAILURE = "Failure in reading Private Key";
    public static final String UNRECOVERABLE_KEY = "Not able to recover key from the Key Store";
    public static final String CERTIFICATE_CONVERSION_FAILED = "Failure in converting Certificate";
    public static final String KEYSTORE_FILE_NOT_FOUND = "Key Store file is not found in the given file path";
    public static final String INVALID_KEY_STORE_DATA = "Invalid Key Store Data";
    public static final String ALIAS_NOT_FOUND = "Alias Name is not found in Key Store";
    public static final String CERTIFICATE_NOT_FOUND = "Certificate is not found in the Key Store";
    public static final String CERTIFICATE_CHAIN_NOT_FOUND = "Certificate Chain is not Found in the Key Store";
    public static final String KEYSTORE_NOT_SUPPORTED = "Key Store is not Supported";
    public static final String CERTIFICATE_NOT_LOADED = "Certificate is not loaded into the Key Store";
    public static final String UNSUPPORTED_KEY_STORE_TYPE = "Key Store type is not supported.";
    public static final String READ_ALIASES_FAILURE = "Failure in reading all aliases from the Key Store";
}
