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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;

/**
 * This interface need to be implemented by the classes where different types of CMP Requests are handled
 * 
 * @author tcschdy
 * 
 */
public interface RequestHandler {

    /**
     * This method is used for generating the CMP Response for the CMP Request sent from CMP Service and dispatch it to the CMPService
     * 
     * @param cMPRequest
     *            Contains the transaction ID,request type and the CMP Request sent from CMP Service
     */
    void handle(CMPRequest cMPRequest);

}
