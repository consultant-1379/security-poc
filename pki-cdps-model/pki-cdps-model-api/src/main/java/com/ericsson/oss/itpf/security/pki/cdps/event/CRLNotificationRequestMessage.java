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
package com.ericsson.oss.itpf.security.pki.cdps.event;

import java.io.Serializable;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.eventtype.EventTypeDefinition;
import com.ericsson.oss.itpf.security.pki.cdps.constants.CDPSModelConstant;

/**
 * CDPS will send CRLNotificationRequestMessage to PKI-manager to  to send notification message for publish and unpublish CRLs when CDPS Service is up
 * 
 * @author xvambur
 */
@EModel(namespace = CDPSModelConstant.NAME_SPACE, name = "CRLNotificationRequestMessage", version = CDPSModelConstant.MODEL_VERSION, description = "CDPS sends an event to PKI Manager to send CRL Notification for publish and unpublish")
@EventTypeDefinition(channelUrn = CDPSModelConstant.CRL_NOTIFICATION_CHANNEL_URN)
public class CRLNotificationRequestMessage implements Serializable{
 
    private static final long serialVersionUID = -3297966306909409643L;

}
