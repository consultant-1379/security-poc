/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.model.topics;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelDefinition;
import com.ericsson.oss.itpf.modeling.annotation.channel.ChannelType;

/**
 * This class defines model for certificate enrollment status topic on which modeled event CertificateEnrollmentStatus is pushed. This modeled channel is a PUBLISH_SUBSCRIBE channel between PKI-RA and
 * AP for sending enrollment status event.
 * 
 * @author xgvgvgv
 *
 */

@EModel(name = "ClusteredCertificateEnrollmentStatusTopic", description = "This topic is used for sending Certificate Enrollment Status Event to AP")
@ChannelDefinition(channelType = ChannelType.PUBLISH_SUBSCRIBE, channelURI = "jms:/topic/ClusteredCertificateEnrollmentStatusTopic")
public class CertificateEnrollmentStatusTopic {

}
