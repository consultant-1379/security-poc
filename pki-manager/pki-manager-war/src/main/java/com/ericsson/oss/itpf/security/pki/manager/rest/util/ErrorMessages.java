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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

public class ErrorMessages {

    public static final String CERTIFICATE_IS_NOT_LOADED = "Certificate could not be loaded in the key store";
    public static final String KEYSTORE_ALGORITHM_IS_NOT_FOUND = "The appropriate data integrity algorithm could not be found while loading the certificate in key store";
    public static final String PROVIDER_IS_NOT_AVAILABLE = "provider requested is not available in the environment";

    public static final String ERROR_OCCURED_IN_UPDATING_DATABASE = "Error occured in updating the database entity";
    public static final String FORMAT_NOT_SUPPORTED = "Format is not supported";
    public static final String UNRECOVERABLE_KEY = "Key cannot be recovered from keystore";

    public static final String ENTITY_NAME_MANDATORY = "Entity Name is required to issue certificate";
    public static final String CERTIFICATE_ID_IS_MANDATORY = "Certificate Id is required to get certificates";

    public static final String CA_NAME_MANDATORY = "CA Name is required";
    public static final String END_ENTITY_NAME_MANDATORY = "Entity Name is required";

    public static final String RE_ISSUE_TYPE_MANDATORY = "ReIssue Type is mandatory";

}
