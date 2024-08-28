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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder;

import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;

/**
 * This class is used to build ErrorInfo
 * 
 * @author tcsdemi
 *
 */
public class TDPSErrorInfoBuilder {

    private String errorMessage;

    /**
     * @param errorMessage
     *            the errorMessage to set
     */
    public TDPSErrorInfoBuilder errorMessage(final String errorMessage) {
        this.errorMessage = errorMessage;
        return this;
    }

    /**
     * This method builds TDPSErrorInfo
     * 
     * @return
     */
    public TDPSErrorInfo build() {
        final TDPSErrorInfo tdpsErrorInfo = new TDPSErrorInfo();
        tdpsErrorInfo.setErrorMessage(errorMessage);
        return tdpsErrorInfo;

    }

}
