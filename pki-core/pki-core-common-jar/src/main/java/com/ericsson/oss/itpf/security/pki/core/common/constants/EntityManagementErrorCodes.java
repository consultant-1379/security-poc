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
package com.ericsson.oss.itpf.security.pki.core.common.constants;

/**
 * This class contains error message constants.
 * 
 */
public class EntityManagementErrorCodes {

    public static final String ENTITY_ALREADY_EXISTS = "Entity already exists.";

    public static final String TRANSACTION_INACTIVE = "Transaction InActive!";

    public static final String OCCURED_IN_UPDATING = " occured in Updating ";

    public static final String INVALID_NAME_FORMAT = "Invalid Name Format!";

    public static final String INVALID_OPERATION = "Invalid Operation!";

    public static final String NOT_FOUND_WITH_ID = " not found with ID: ";

    public static final String OCCURED_IN_DELETING = " occured in Deleting ";

    public static final String ID_OR_NAME_SHOULD_PRESENT = "Atleast id or name should be specified!";

    public static final String INVALID_ID_OR_NAME = "Invalid id or name specified!";

    public static final String CA_ENTITY_NOT_FOUND = "CA Entity doesnot exist ";

    public static final String CA_ENTITY_IS_DELETED = "CA Entity is already deleted";

    public static final String CA_ENTITY_IS_ACTIVE = "CA Entity is active so cannot be deleted";

    public static final String ENTITY_IS_ACTIVE_UNDER_CA = "Entity cannot be deleted because there are active entities present under CA ";

    public static final String CAENTITY_IS_ACTIVE_UNDER_CA = "CA Entity cannot be deleted because there are active entities present under CA";

    public static final String UNEXPECTED_ERROR = "Unexpected error ";

    public static final String ENTITY_IS_DELETED = "Entity is already deleted.";

    public static final String ENTITY_IS_ACTIVE = "Entity cannot be deleted because it is in ACTIVE status.";

    public static final String ENTITY_IS_REISSUED = "Entity cannot be deleted because it is in REISSUE status.";

    public static final String INVALID_CASTATUS = "Invalid CA Status";

    public static final String CA_ISNOTNULL = "Certificate Authority cannot be null";

    public static final String ENTITY_ISNOTNULL = "EntityInfo should not be null ";

    public static final String NAME_ISNOTNULL = "Name cannot be null";

    public static final String NAME_ISNOTEMPTY = "Name cannot be empty";

}
