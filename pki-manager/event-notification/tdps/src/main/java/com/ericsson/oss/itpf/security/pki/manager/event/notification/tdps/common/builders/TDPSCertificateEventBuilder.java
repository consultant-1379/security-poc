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

import java.util.List;

import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * This class is an CertificateEventBuilder which will build TDPSCertificateEvent and then this will be send over the queue wherever it is used.
 * 
 * @author tcsdemi
 *
 */
public class TDPSCertificateEventBuilder {
    private TDPSOperationType publishType;
    private List<TDPSCertificateInfo> tdpsCertificateInfos;

    /**
     * Sets the publishType for building TDPSCertificateEventBuilder
     * 
     * @param publishType
     * @return
     */
    public TDPSCertificateEventBuilder publishType(final TDPSOperationType publishType) {
        this.publishType = publishType;
        return this;
    }

    /**
     * Sets the CertificateInfo list for building TDPSCertificateEventBuilder
     * 
     * @param tdpsCertificateInfos
     * @return
     */
    public TDPSCertificateEventBuilder tDPSCertificateInfo(final List<TDPSCertificateInfo> tdpsCertificateInfos) {
        this.tdpsCertificateInfos = tdpsCertificateInfos;
        return this;
    }

    /**
     * This method builds the actual TDPSCertificateEvent which is the modeled event.
     * 
     * @return
     */
    public TDPSCertificateEvent build() {
        final TDPSCertificateEvent tdpsCertificateEvent = new TDPSCertificateEvent();
        tdpsCertificateEvent.setTdpsOperationType(publishType);
        tdpsCertificateEvent.setTdpsCertificateInfos(tdpsCertificateInfos);
        return tdpsCertificateEvent;
    }
}