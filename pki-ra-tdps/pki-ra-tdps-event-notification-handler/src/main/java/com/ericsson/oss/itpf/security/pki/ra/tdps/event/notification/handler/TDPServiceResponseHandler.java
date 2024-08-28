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
package com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.handler;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSResponse;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSEntityDataMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.TDPSResponseMapper;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder.TDPSAcknowledgementEventBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.builder.TDPSErrorInfoBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender.TDPSAcknowledgementEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.eserviceref.TDPSLocalEServiceHolder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSErrorInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSOperationType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse;

/**
 * This class will handle "TDPServiceResponse" response which will be consumed by the Listeners
 * 
 * @author tcsdemi
 *
 */
public class TDPServiceResponseHandler {

    @Inject
    TDPSLocalEServiceHolder eServiceHolder;

    @Inject
    TDPSEntityDataMapper tDPSEntityMapper;

    @Inject
    TDPSResponseMapper tDPSResponseMapper;

    @Inject
    TDPSAcknowledgementEventSender tdpsAcknowledgementEventSender;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is an Asynchronous method which will handle "TDPServiceResponse" to persist all the CA and entity Certificates in DB.
     * 
     * @param tdpsServiceResponse
     *            Modeled event consisting of List<CertificateInfo>
     */

    public void handle(final TDPServiceResponse tdpsServiceResponse) {
        TDPSAcknowledgementEvent tDPSAcknowledgementEvent = null;

        final List<TDPSCertificateInfo> endEntityTrusts = tdpsServiceResponse.getTdpsCertificateInfoList();
        final List<TDPSEntityData> tdpsEntities = tDPSEntityMapper.fromModel(endEntityTrusts);
        final List<TDPSCertificateInfo> tdpsCertificateInfos = tDPSEntityMapper.toModel(tdpsEntities);

        try {
            eServiceHolder.getTDPSLocalService().persistTdpsEntities(tdpsEntities);
            tDPSAcknowledgementEvent = (new TDPSAcknowledgementEventBuilder()).tDPSResponseType(tDPSResponseMapper.toModel(TDPSResponse.SUCCESS)).tDPSCertificateInfoList(tdpsCertificateInfos)
                    .tDPSOperationType(TDPSOperationType.PUBLISH).build();
        } catch (Exception persistenceException) {
            systemRecorder.recordError("TDPS_SERVICE_STARTUP.PUBLISHED_ENTITIES_FAILED", ErrorSeverity.ERROR, "Publish Certificates to TDPS",
                    "Trusted Certificates of Entity which invokes TDPS", persistenceException.getMessage());
            logger.error("PersistenceException occured, sending back acknowledgment event with FAILURE status");
            logger.debug("Exception stacktrace: ", persistenceException);

            final TDPSErrorInfo tDPSErrorInfo = (new TDPSErrorInfoBuilder()).errorMessage(persistenceException.getMessage()).build();
            tDPSAcknowledgementEvent = (new TDPSAcknowledgementEventBuilder()).tDPSResponseType(tDPSResponseMapper.toModel(TDPSResponse.FAILURE)).tDPSErrorInfo(tDPSErrorInfo)
                    .tDPSCertificateInfoList(tdpsCertificateInfos).tDPSOperationType(TDPSOperationType.PUBLISH).build();
        } finally {
            tdpsAcknowledgementEventSender.send(tDPSAcknowledgementEvent);
        }
    }
}