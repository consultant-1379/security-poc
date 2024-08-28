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
package com.ericsson.oss.itpf.security.pki.cdps.notification.events;

import java.util.Date;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.*;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender;
import com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CACertificateInfoValidator;
import com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation.CRLInstrumentationBean;

/**
 * UnpublishCRLEvent class will UnPublish the CRL into CDPS and sends the acknowledgement to PKI Manager over a ClusteredCRLAcknowledgementChannel
 * 
 * @author xjagcho
 * 
 */
public class UnpublishCRLEvent {

    @Inject
    CRLAcknowledgementSender crlAcknowledgementSender;

    @Inject
    CACertificateInfoValidator caCertificateInfoValidator;

    @Inject
    CRLDistributionPointLocalServiceWrapper crlDistributionPointLocalServiceWrapper;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    CRLInstrumentationBean crlInstrumentationBean;

    /**
     * This method process the list of CRL information to persist and also sends the CRL ResponseAckMessage to the ClusteredCRLAcknowledgementChannel
     * 
     * Also the success and failure operations are recorded for DDC DDP
     * 
     * @param caCertificateInfos
     *            it holds caName and serialNumber
     * @param unpublishReasonType
     *            it holds the reason type of the UnPublish CRL
     */
    public void execute(final List<CACertificateInfo> caCertificateInfos, final UnpublishReasonType unpublishReasonType) {
        CDPSResponseType cdpsResponseType = CDPSResponseType.FAILURE;

        crlInstrumentationBean.setUnPublishMethodInvocations();
        try {
            caCertificateInfoValidator.validate(caCertificateInfos);

            crlDistributionPointLocalServiceWrapper.unPublishCRL(caCertificateInfos);
            cdpsResponseType = CDPSResponseType.SUCCESS;

            crlInstrumentationBean.setUnPublishMethodSuccess();
            systemRecorder.recordEvent("PKI_CDPS.CRL_UNPUBLISHED", EventLevel.COARSE, "CDPSService", "CDPSService",
                    "CRLs are unpublished successfully for the CA names and certificate serial numbers: " + caCertificateInfos);
        } catch (CRLValidationException crlValidationException) {
        logger.error("Error occured CA CertificateInfo object validation fails{}", crlValidationException.getMessage());
        logger.debug("Error occured CA CertificateInfo object validation fails ", crlValidationException);
            systemRecorder.recordError("PKI_CDPS.CACERTINFO_VALIDATION_FAIL", ErrorSeverity.ERROR, "CDPSService", "CDPSService", "CA CertificateInfo object validation fails during CRL Unpublish");
        } catch (Exception exception) {
        logger.error("Error occured during unpublish the CRL : {}", exception.getMessage());//during unpublishing of CRLs for" and print CA name and serial numbers.
        logger.debug("Error occured during unpublish the CRL : ", exception);
            systemRecorder.recordError("PKI_CDPS.UNPUBLISH_CRL_ERROR", ErrorSeverity.ERROR, "CDPSService", "CDPSService", "Error occured during unpublishing of CRLs for " + caCertificateInfos);
        }

        if (cdpsResponseType == CDPSResponseType.FAILURE) {
            profiledUnpublishCRLEventFailure(caCertificateInfos);
        }

        final CRLResponseAckMessage crlResponseAckMessage = (new CRLResponseAckMessageBuilder()).caCertificateInfos(caCertificateInfos).cdpsOperationType(CDPSOperationType.UNPUBLISH)
                .unpublishReasonType(unpublishReasonType).cdpsResponseType(cdpsResponseType).build();
        crlAcknowledgementSender.sendMessage(crlResponseAckMessage);
    }

    /**
     * This method logs the DDC error message for each cdpsEntityData object in the List of CRLInfo
     *
     * @param crlInfoList
     *
     * @return List of CACertificateInfo it contains caName and serialNumber
     */
    private void profiledUnpublishCRLEventFailure(final List<CACertificateInfo> crlInfoList) {
        try {
            for (CACertificateInfo caCertificateInfo : crlInfoList) {
                systemRecorder.recordEvent("PKI_CDPS.RECORD_FAILURES", EventLevel.COARSE, "CDPSService", "CDPSService", "OperationType=UNPUBLISH, IssuerName=" + caCertificateInfo.getCaName()
                        + ", SerialNumber=" + caCertificateInfo.getCertificateSerialNumber() + ", TimeStamp=" + (new Date()) + "]");
            }
        } catch (Exception exception) {
        logger.error("Error occured while recording the DDC error message", exception.getMessage());
        logger.debug("Error occured while recording the DDC error message ", exception);
        }
    }
}
