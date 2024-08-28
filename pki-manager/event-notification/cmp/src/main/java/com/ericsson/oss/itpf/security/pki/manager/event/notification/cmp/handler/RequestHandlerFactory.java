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
 * This interface must be implemented by the classes where there is a need to find the request type of the CMP Request sent from the CMP SErvice
 * 
 * @author tcschdy
 * 
 */
public interface RequestHandlerFactory {

    /**
     * @param cMPRequest
     *            Model Parameter for CMPRequest EventType which contains the transaction ID and the CMP Request object sent from CMP Service
     * @return RequestHandler that should be used for generating the CMP Response depending upon the request type
     */
    RequestHandler getRequestHandler(final CMPRequest cMPRequest);
}
