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
package com.ericsson.oss.itpf.security.pki.ra.tdps.model.channel;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelDefinition;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants.TDPSModelConstants;

/**
 * This class defines model for request Channel on which modeled event TDPServiceRequest is pushed. This modeled channel is a POINT_TO_POINT channel between PKI-RA and PKI-Manager serving only CMP
 * request for certificate.
 * 
 * @author tcsdemi
 *
 */
@EModel(name = "ClusteredTDPServiceRequestChannel", description = "This channel will be used for sending TDPSRequestMessage to PKIManager")
@ChannelDefinition(channelType = ChannelType.POINT_TO_POINT, channelURI = TDPSModelConstants.REQUEST_CHANNEL_URI)
public class TDPServiceRequestChannel {
}