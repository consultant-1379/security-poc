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
package com.ericsson.oss.itpf.security.pki.cdps.common.constant;

/**
 * This class contains different types of error constant messages
 * 
 * @author xjagcho
 *
 */
public class ErrorMessages {

    public static final String ERR_INTERNAL_ERROR = "Exception occured while retrieving the CRL";
    public static final String ERR_EMPTY_CANAME = "CAName should not be empty in the URL";
    public static final String ERR_EMPTY_CACERTSERIALNUMBER = "CACertSerialNumber should not be empty in the URL";
    public static final String ERR_IO_EXCEPTION = "Exception occured while writing crl content to the file";
    public static final String ERR_CRL_EXPIRED = "Requested CRL is Expired";
    public static final String ERR_CRL_NOT_FOUND = "Couldn't find the crl with the given caName and certSerialNumber";
    public static final String ERR_CRL_CONVERSION = "Exception while converting the CRL byte array into X509CRL";
    
    public static final String FAILED_TO_RECREATE_TIMER = "Failed to recreate timer for the changed configuration parameter ";
}
