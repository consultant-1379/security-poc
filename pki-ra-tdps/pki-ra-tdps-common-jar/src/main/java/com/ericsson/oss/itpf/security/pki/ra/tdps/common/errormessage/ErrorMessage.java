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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.errormessage;

/**
 * This class includes all the error Messages for trust distribution service
 * 
 * @author tcsdemi
 *
 */
public class ErrorMessage {

    private ErrorMessage() {
    }

    public static final String ERR_NOT_PUBLISHED_TO_TDPS = "None of the certificates sent to TDPS are published due to internal DB Error";
    public static final String ERR_MISSING_PARAMS = "Mandatory parameters are missing, EntityType, EntityName and CertificateSerialNumber should be provided";
    public static final String ERR_CERTIFICATE_CAN_NOT_BE_WRITTEN = "IOException while writing certificate into file";
    public static final String ERR_CERTIFICATE_NOT_FOUND_IN_DB = "Certificate is not found in DB";
    public static final String ERR_ENTITY_MANAGER_NULL = "Entity Manager is null";
    public static final String ERR_NULL_ISSUER_NAME = "Given IssuerName is null or not provided in the URL ";
    public static final String ERR_NULL_ENTITY_NAME = "Given EntityName is null or not provided in the URL";
    public static final String ERR_NULL_CERTIFICATE_ID = "Given CertificateSerial number is null or not provided in the URL";
    public static final String ERR_NULL_ENTITY_TYPE = "Given entity type is null or not provided in the URL";
    public static final String ERR_NULL_CERTIFICATE_STATUS = "Given Certificate status  is null or not provided in the URL";
    public static final String ERR_INVALID_ENTITY_TYPE = "Entity Type can only be either CA_ENTITY or ENTITY,check the URL again";
    public static final String ERR_INVALID_CERTIFICATE_STATUS_TYPE = "Certificate status Type can only be either ACTIVE or INACTIVE,check the URL again";

}
