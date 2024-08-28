/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest;

import java.util.List;

import com.ericsson.oss.services.scriptengine.spi.dtos.AbstractDto;

public class Response {

    private String requestId;
    private List<AbstractDto> response;
 
    public Response(final String requestId, final List<AbstractDto> response) {
        super();
        this.requestId = requestId;
        this.response = response;
    }

    /**
     * @return the requestId
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(final String requestId) {
        this.requestId = requestId;
    }

    /**
     * @return the response
     */
    public List<AbstractDto> getResponse() {
        return response;
    }

    /**
     * @param response the response to set
     */
    public void setResponse(final List<AbstractDto> response) {
        this.response = response;
    }
    
    
}
