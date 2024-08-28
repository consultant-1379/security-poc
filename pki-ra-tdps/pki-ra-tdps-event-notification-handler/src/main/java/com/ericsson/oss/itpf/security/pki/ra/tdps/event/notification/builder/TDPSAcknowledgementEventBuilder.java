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

import java.util.List;

import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

/**
 * This class builds AcknowledgementEvent (modeled event)
 * 
 * @author tcsdemi
 *
 */
public class TDPSAcknowledgementEventBuilder {

    private TDPSErrorInfo tdpsErroInfo;
    private TDPSResponseType tdpsResponseType;
    private List<TDPSCertificateInfo> certificateInfoList;
    private TDPSOperationType tdpsOperationType;

    /**
     * sets operationType
     * 
     * @param errorMessage
     *            the errorMessage to set
     */
    public TDPSAcknowledgementEventBuilder tDPSOperationType(final TDPSOperationType tdpsOperationType) {
        this.tdpsOperationType = tdpsOperationType;
        return this;
    }

    /**
     * sets errorMessage
     * 
     * @param errorMessage
     *            the errorMessage to set
     */
    public TDPSAcknowledgementEventBuilder tDPSErrorInfo(final TDPSErrorInfo tdpsErroInfo) {
        this.tdpsErroInfo = tdpsErroInfo;
        return this;
    }

    /**
     * sets tdpsResponseType
     * 
     * @param tdpsResponseType
     * @return
     */
    public TDPSAcknowledgementEventBuilder tDPSResponseType(final TDPSResponseType tdpsResponseType) {
        this.tdpsResponseType = tdpsResponseType;
        return this;
    }

    /**
     * Sets certificateInfoList
     * 
     * @param certificateInfoList
     * @return
     */
    public TDPSAcknowledgementEventBuilder tDPSCertificateInfoList(final List<TDPSCertificateInfo> certificateInfoList) {
        this.certificateInfoList = certificateInfoList;
        return this;
    }

    /**
     * This build method is used to set all attributes in the modeled event TDPSAcknowledgementEvent
     * 
     * @return
     */
    public TDPSAcknowledgementEvent build() {
        final TDPSAcknowledgementEvent tDPSAcknowledgementEvent = new TDPSAcknowledgementEvent();
        tDPSAcknowledgementEvent.setErrorInfo(tdpsErroInfo);
        tDPSAcknowledgementEvent.setTdpsCertificateInfoList(certificateInfoList);
        tDPSAcknowledgementEvent.setResponseType(tdpsResponseType);
        tDPSAcknowledgementEvent.setTdpsOperationType(tdpsOperationType);
        return tDPSAcknowledgementEvent;

    }

}
