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
package com.ericsson.oss.itpf.security.pki.ra.tdps.model.events;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants.TDPSModelConstants;

/**
 * This class defines model event for TDPSServiceRequest event. This is just a notification with no attribute to be sent, since certificates for all entity types needs to be sent.
 * 
 * @author tcsdemi
 *
 */
@EModel(namespace = TDPSModelConstants.NAME_SPACE, name = "TDPServiceRequest", version = TDPSModelConstants.VERSION, description = "This event is just to notify PKi-Manager that it has to send a response with all entity/ca certificates to Trust distribution point service")
@EventTypeDefinition(channelUrn = TDPSModelConstants.REQUEST_CHANNEL_URN)
public class TDPServiceRequest implements Serializable {

    private static final long serialVersionUID = -3100055413364639876L;

}
