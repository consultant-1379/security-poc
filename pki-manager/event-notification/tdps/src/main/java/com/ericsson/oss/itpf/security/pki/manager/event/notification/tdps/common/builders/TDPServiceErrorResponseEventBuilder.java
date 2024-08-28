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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders;

import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * This class builds an error response which can be sent over the event bus using an error cause or message.
 * 
 * @author tcsdemi
 *
 */
public class TDPServiceErrorResponseEventBuilder {
    private String cause;

    /**
     * sets the cause or error message why response building failed .
     * 
     * @param cause
     * @return
     */
    public TDPServiceErrorResponseEventBuilder cause(final String cause) {
        this.cause = cause;
        return this;
    }

    /**
     * This method will simply build an error event which needs to be sent over the event bus. But before using build method, cause() needs to be set.
     * 
     * @return
     */
    public TDPServiceResponse buildErroredResponse() {
        final TDPSErrorInfo tdpsErrorInfo = new TDPSErrorInfo();
        tdpsErrorInfo.setErrorMessage(cause);

        final TDPServiceResponse tDPServiceResponse = new TDPServiceResponse();

        tDPServiceResponse.setResponseType(TDPSResponseType.FAILURE);
        tDPServiceResponse.setErrorInfo(tdpsErrorInfo);

        return tDPServiceResponse;
    }
}