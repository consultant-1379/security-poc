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
package com.ericsson.oss.itpf.security.pki.ra.scep.constants;

/**
 * This class contains constants which can be used while processing request and building response.
 *
 * @author xtelsow
 */
public final class Constants {

    private Constants(){

    }

    public static final String MESSAGE_TYPE_OID = "2.16.840.1.113733.1.9.2";
    public static final String STATUS_OID = "2.16.840.1.113733.1.9.3";
    public static final String FAIL_INFO_OID = "2.16.840.1.113733.1.9.4";
    public static final String SENDER_NONCE = "2.16.840.1.113733.1.9.5";
    public static final String RECEPIENT_NONCE = "2.16.840.1.113733.1.9.6";
    public static final String TRANSACTION_ID = "2.16.840.1.113733.1.9.7";

    public static final String GETCACERT_CONTENT_TYPE = "application/x-x509-ca-ra-cert";
    public static final String GETCACERTCHAIN_CONTENT_TYPE = "application/x-x509-ca-ra-cert-chain";
    public static final String PKIOPERATION_CONTENT_TYPE = "application/x-pki-message";

    public static final String SUPPORTED_ALGORITHMS = "ListOfAlgorithms";
    public static final String STORE_PASSWORD = "StorePassword";

    public static final String STORE_TYPE_KEY_STORE = "KeyStore";
    public static final String STORE_TYPE_TRUST_STORE = "TrustStore";
    public static final String DB_CLEANUP_SCHEDULER_INFO = "DBCleanUpSchedulerInfo";

}
