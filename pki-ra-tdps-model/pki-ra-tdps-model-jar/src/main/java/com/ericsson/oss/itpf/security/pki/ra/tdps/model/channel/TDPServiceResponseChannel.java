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
 * This class defines model for response Channel on which modeled event TDPSServiceResponse and TDPSCertificateEvent is pushed. This modeled channel is a POINT_TO_POINT channel between PKI-RA and
 * PKI-Manager serving only for sending CMPResponse to PKI-RA.
 * 
 * @author tcsdemi
 *
 */
@EModel(name = "ClusteredTDPServiceResponseChannel", description = "This Channel is used for sending TDPSRsponseMEssage from PKiManager")
@ChannelDefinition(channelType = ChannelType.POINT_TO_POINT, channelURI = TDPSModelConstants.RESPONSE_CHANNEL_URI)
public class TDPServiceResponseChannel {

}
