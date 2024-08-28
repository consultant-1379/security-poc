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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.event;

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSResponse;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder.TDPSAcknowledgementEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.instrumentation.TDPSInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender.TDPSAcknowledgementEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.eserviceref.TDPSLocalEServiceHolder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * This class is used for publishing certificate in TDPS DB
 * 
 * @author tcsdemi
 *
 */
public class PublishTDPSCertificateEvent {

    @Inject
    TDPSLocalEServiceHolder eServiceHolder;

    @Inject
    TDPSEntityDataMapper tDPSEntityDataMapper;

    @Inject
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Inject
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Inject
    TDPSResponseMapper tDPSResponseMapper;

    @Inject
    TDPSAcknowledgementEventSender tdpsAcknowledgementEventSender;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    TDPSInstrumentationBean tdpsInstrumentationBean;


    /**
     * This method is used to execute certificate event with publish operation type.
     * 
     * @param tDPSCertificateEvent
     */
    public void execute(final TDPSCertificateEvent tDPSCertificateEvent) {
        for (TDPSCertificateInfo eachcertificateInfo : tDPSCertificateEvent.getTdpsCertificateInfos()) {
            try {
                tdpsInstrumentationBean.setPublishInvocations();
                eServiceHolder.getTDPSLocalService().publishTDPSCertificates(eachcertificateInfo);
                sendAcknowledgementEvent(eachcertificateInfo, TDPSResponse.SUCCESS);
                systemRecorder.recordEvent("TDPS_SERVICE.PUBLISH_TO_TDPS_FINISHED", EventLevel.COARSE, "Publish Certificates to TDPS",
                        "Trusted Certificates of Entity which invokes TDPS",
                        "Successfully Published the Certificate of [" + eachcertificateInfo.getEntityName() + "] of type" + "["
                                + eachcertificateInfo.getTdpsEntityType().name() + "]'");
            } catch (Exception exception) {
                tdpsInstrumentationBean.setPublishFailures();
                logger.error("Certificates couldn't be published for entityName {} of type {}, to TDPS", eachcertificateInfo.getEntityName(), eachcertificateInfo.getTdpsEntityType());
                logger.warn("Certificates couldn't be published to TDPS due to ", exception);
                sendAcknowledgementEvent(eachcertificateInfo, TDPSResponse.FAILURE);
                systemRecorder.recordError("TDPS_SERVICE.PUBLISHED_CERTIFICATES_FAILED", ErrorSeverity.ERROR, "Publish Certificates to TDPS",
                        "Trusted Certificates of Entity which invokes TDPS", exception.getMessage() + "[" + eachcertificateInfo.getEntityName() + "]"
                                + "[" + eachcertificateInfo.getTdpsEntityType().name() + "]'");
                systemRecorder.recordEvent("TDPS_SERVICE.RECORD_FAILURES", EventLevel.COARSE, "Publish Certificates to TDPS",
                        "Trusted Certificates of Entity which invokes TDPS",
                        "[OperationType=PUBLISH, CertificateStatus=" + eachcertificateInfo.getTdpsCertificateStatusType() + ", IssuerName="
                                + eachcertificateInfo.getIssuerName() + ", SerialNumber=" + eachcertificateInfo.getSerialNumber() + ", TimeStamp="
                                + (new Date()) + "]");
            }
        }
    }

    private void sendAcknowledgementEvent(final TDPSCertificateInfo certificateInfo, final TDPSResponse tdpsResponse) {
        final List<TDPSCertificateInfo> certificateInfoList = new ArrayList<>();
        certificateInfoList.add(certificateInfo);

        final TDPSAcknowledgementEvent tDPSAcknowledgementEvent = (new TDPSAcknowledgementEventBuilder()).tDPSResponseType(tDPSResponseMapper.toModel(tdpsResponse))
                .tDPSCertificateInfoList(certificateInfoList).tDPSOperationType(TDPSOperationType.PUBLISH).build();
        tdpsAcknowledgementEventSender.send(tDPSAcknowledgementEvent);
    }
}
