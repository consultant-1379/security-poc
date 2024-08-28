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
package com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants;

/**
 * This class defines the constant values used across CMP model.
 * 
 * @author tcsdemi
 *
 */
public class TDPSModelConstants {

    public static final String VERSION = "1.0.0";
    public static final String NO_ERROR_INFO = "No error information";
    public static final String NAME_SPACE = "pki-ra-tdps";
    public static final String RESPONSE_CHANNEL_URN = "//global/ClusteredTDPServiceResponseChannel";
    public static final String REQUEST_CHANNEL_URN = "//global/ClusteredTDPServiceRequestChannel";
    public static final String ACKNOWLEDGE_CHANNEL_URN = "//global/ClusteredTDPSAcknowledgementChannel";
    public static final String CERTIFICATE_EVENT_CHANNEL_URN = "//global/ClusteredTDPSCertificateEventChannel";

    public static final String RESPONSE_CHANNEL_URI = "jms:/queue/ClusteredTDPServiceResponseChannel";
    public static final String REQUEST_CHANNEL_URI = "jms:/queue/ClusteredTDPServiceRequestChannel";
    public static final String ACKNOWLEDGE_CHANNEL_URI = "jms:/queue/ClusteredTDPSAcknowledgementChannel";
    public static final String CERTIFICATE_EVENT_CHANNEL_URI = "jms:/queue/ClusteredTDPSCertificateEventChannel";
}
