/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pkira.scep.channel;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelDefinition;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelType;

@EModel(name = "ClusteredScepRequestChannel", description = "Scep Request Channel" + "SceprequestMessage from pki-ra-scep to pki-manager")
@ChannelDefinition(channelType = ChannelType.POINT_TO_POINT, channelURI = "jms:/queue/ClusteredScepRequestChannel")
/**
 * @author xananer
 * 
 * ScepRequestChannel to send the CSR and TransactionId to pki-manager . 
 * This channel is use to send the pkcs request for the generation of the certificate. 
 * The csr sent over the channel will be used in the generation of the certificate
 */
public class ScepRequestChannel {

}
