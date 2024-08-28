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
package com.ericsson.oss.itpf.security.pki.cdps.constants;

/**
 *
 * This class contains all the CDPS_Model Constants which will be used in CDPS.
 *
 * @author xnarsir
 *
 */
public class CDPSModelConstant {
    public static final String MODEL_VERSION = "1.0.0";
    public static final String NAME_SPACE = "pki-cdps";

    public static final String CRL_RESPONSE_ACK_CHANNEL_URI = "jms:/queue/ClusteredCRLResponseAckChannel";
    public static final String CRL_NOTIFICATION_CHANNEL_URI = "jms:/queue/ClusteredCRLNotificationChannel";
    public static final String CRL_RESPONSE_CHANNEL_URI = "jms:/queue/ClusteredCRLResponseChannel";
    public static final String CRL_REQUEST_CHANNEL_URI = "jms:/queue/ClusteredCRLRequestChannel";

    public static final String CRL_RESPONSE_ACK_CHANNEL_URN = "//global/ClusteredCRLResponseAckChannel";
    public static final String CRL_NOTIFICATION_CHANNEL_URN = "//global/ClusteredCRLNotificationChannel";
    public static final String CRL_RESPONSE_CHANNEL_URN = "//global/ClusteredCRLResponseChannel";
    public static final String CRL_REQUEST_CHANNEL_URN = "//global/ClusteredCRLRequestChannel";

}
