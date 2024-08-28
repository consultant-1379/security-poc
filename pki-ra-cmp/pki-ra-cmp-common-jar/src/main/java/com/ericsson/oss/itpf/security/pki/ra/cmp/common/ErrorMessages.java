/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

/**
 * This class includes all the error Messages which are common across all
 * modules.
 *
 * @author xvadyas
 *
 */
public class ErrorMessages {

    private ErrorMessages() {
    }

    public static final String FAILED_TO_UNREGISTER_RESOURCES_LISTENERS = "Not able to unregister resources listeners with listen directory path location for internal/external trusts and CRL due to {}";
    public static final String FAILED_TO_REGISTER_RESOURCES_LISTENERS = "Not able to register resources listeners. New/updated Certficates and CRLs will be not available in CMP {}";
    public static final String FAILED_TO_INITIALIZE_CA_CERTIFICATES = "Exception occurred while initializing CA Certificates due to {}";
    public static final String FAILED_TO_INITIALIZE_VENDOR_CERTIFICATES = "Exception occurred while initializing Vendor Certificates due to {}";
}
