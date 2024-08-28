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
 * This class is used for un publishing certificate from TDPS DB
 * 
 * @author tcsdemi
 *
 */
public class UnPublishTDPSCertficateEvent {

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
     * This method is used to execute certificate event with unpublish operation type. Based on the entityName/issuerName/certificateSerialID entitydata is fetched, incase record does not exists then
     * exception is thrown
     * 
     * @param tDPSCertificateEvent
     */

    public void execute(final TDPSCertificateEvent tDPSCertificateEvent) {
        TDPSAcknowledgementEvent tDPSAcknowledgementEvent = null;
        for (TDPSCertificateInfo eachcertificateInfo : tDPSCertificateEvent.getTdpsCertificateInfos()) {

            final List<TDPSCertificateInfo> certificateInfoList = new ArrayList<TDPSCertificateInfo>();
            certificateInfoList.add(eachcertificateInfo);
            try {
                tdpsInstrumentationBean.setUnPublishInvocations();
                eServiceHolder.getTDPSLocalService().unPublishTDPSCertificates(eachcertificateInfo);
                tDPSAcknowledgementEvent = (new TDPSAcknowledgementEventBuilder()).tDPSResponseType(tDPSResponseMapper.toModel(TDPSResponse.SUCCESS))
                        .tDPSCertificateInfoList(certificateInfoList).tDPSOperationType(TDPSOperationType.UNPUBLISH).build();
                systemRecorder.recordEvent("TDPS_SERVICE.UNPUBLISH_TO_TDPS_FINISHED", EventLevel.COARSE, "UnPublish Certificates from TDPS",
                        "Trusted Certificates of Entity which invokes TDPS",
                        "Successfully UnPublished the Certificate of [" + eachcertificateInfo.getEntityName() + "] of type" + "["
                                + eachcertificateInfo.getTdpsEntityType().name() + "]'");

            } catch (Exception exception) {
                tDPSAcknowledgementEvent = (new TDPSAcknowledgementEventBuilder()).tDPSResponseType(tDPSResponseMapper.toModel(TDPSResponse.FAILURE))
                        .tDPSCertificateInfoList(certificateInfoList).tDPSOperationType(TDPSOperationType.UNPUBLISH).build();
                tdpsInstrumentationBean.setUnPublishFailures();
                systemRecorder.recordError("TDPS_SERVICE.UNPUBLISHED_CERTIFICATES_FAILED", ErrorSeverity.ERROR, "UnPublish Certificates from TDPS",
                        "Trusted Certificates of Entity which invokes TDPS", exception.getMessage() + "[" + eachcertificateInfo.getEntityName() + "]"
                                + "[" + eachcertificateInfo.getTdpsEntityType().name() + "]'");
                logger.error(
                        "Certificate with entity name as {} with certificate serialNo as {} was not found in TDPS. Hence assuming it was already unpublished",
                        eachcertificateInfo.getEntityName(), eachcertificateInfo.getSerialNumber());
                logger.warn("Certificate was not found in TDPS due to ", exception);
                systemRecorder.recordEvent("TDPS_SERVICE.RECORD_FAILURES", EventLevel.COARSE, "UnPublish Certificates from TDPS",
                        "Trusted Certificates of Entity which invokes TDPS",
                        "[OperationType=UNPUBLISH, CertificateStatus=" + eachcertificateInfo.getTdpsCertificateStatusType() + ", IssuerName="
                                + eachcertificateInfo.getIssuerName() + ", SerialNumber=" + eachcertificateInfo.getSerialNumber() + ", TimeStamp="
                                + (new Date()) + "]");
            } finally {
                tdpsAcknowledgementEventSender.send(tDPSAcknowledgementEvent);
            }
        }

    }
}
