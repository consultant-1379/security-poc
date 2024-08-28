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
package com.ericsson.oss.itpf.security.pki.cdps.channel;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelDefinition;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelType;
import com.ericsson.oss.itpf.security.pki.cdps.constants.CDPSModelConstant;

/**
 * ClusteredCRLResponseAckChannel sends the CRLAcknowledgemenet Message to PKI Manager listener over this channel.
 * 
 * @author xnarsir
 */

@EModel(name = "ClusteredCRLResponseAckChannel", description = "CRL Response Ack Channel")
@ChannelDefinition(channelType = ChannelType.POINT_TO_POINT, channelURI = CDPSModelConstant.CRL_RESPONSE_ACK_CHANNEL_URI)
public class ClusteredCRLResponseAckChannel {

}
