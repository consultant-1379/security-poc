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

import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.*;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLDistributionPointServiceException;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSOperationType;
import com.ericsson.oss.itpf.security.pki.cdps.edt.CDPSResponseType;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseAckMessage;
import com.ericsson.oss.itpf.security.pki.cdps.notification.CRLAcknowledgementSender;
import com.ericsson.oss.itpf.security.pki.cdps.notification.builders.CRLResponseAckMessageBuilder;
import com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators.CRLInfoValidator;
import com.ericsson.oss.itpf.security.pki.cdps.notification.instrumentation.CRLInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;

/**
 * PublishCRLEvent class will publish the CRL into CDPS and sends the acknowledgement to PKI Manager over a ClusteredCRLAcknowledgementChannel
 * 
 * @author xjagcho
 *
 */
public class PublishCRLEvent {

    @Inject
    CRLAcknowledgementSender crlAcknowledgementSender;

    @Inject
    CRLInfoValidator crlInfoValidator;

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
     * @param crlInfoList
     *            it contains the CACertificateInfo it holds caName and serialNumber and encodedCRL
     */
    public void execute(final List<CRLInfo> crlInfoList) {
        List<CACertificateInfo> caCertificateInfos;
        CDPSResponseType cdpsResponseType = CDPSResponseType.FAILURE;

        caCertificateInfos = extractCACertificateInfos(crlInfoList);

        try {
            crlInfoValidator.validate(crlInfoList);

            crlDistributionPointLocalServiceWrapper.publishCRL(crlInfoList);
            cdpsResponseType = CDPSResponseType.SUCCESS;

            crlInstrumentationBean.setPublishMethodSuccess();
            systemRecorder.recordEvent("PKI_CDPS.CRL_PUBLISHED", EventLevel.COARSE, "CDPSService", "CDPSService", "List of CRL information published successfully " + caCertificateInfos);
        } catch (CRLValidationException crlValidationException) {
        logger.error("Error occured if CRL Info object validation fails:{}", crlValidationException.getMessage());
        logger.debug("Error occured if CRL Info object validation fails: ", crlValidationException);
        systemRecorder.recordError("PKI_CDPS.CRL_INFO_VALIDATION_FAIL", ErrorSeverity.ERROR, "CDPSService", "CDPSService", "CRL Info object validation fails during CRL Publish");
        } catch (CRLDistributionPointServiceException cRLDistributionPointServiceException) {
        logger.error("Error occured during DB operation {}", cRLDistributionPointServiceException.getMessage());
        logger.debug("Error occured during DB operation ", cRLDistributionPointServiceException);
        systemRecorder.recordError("PKI_CDPS.DB_OPEARTION_ERROR", ErrorSeverity.ERROR, "CDPSService", "CDPSService", "Error occured during DB operation in CRL Publish");
        } catch (Exception exception) {
        logger.error("Error occured during publish the CRL : {}", exception.getMessage());
        logger.debug("Error occured during publish the CRL : ", exception);
        systemRecorder.recordError("PKI_CDPS.PUBLISH_CRL_ERROR", ErrorSeverity.ERROR, "CRLClient", "CDPSService", "Error occured during publish the CRL " + caCertificateInfos);
        }

        if (cdpsResponseType == CDPSResponseType.FAILURE) {
            profiledPublishCRLEventFailure(crlInfoList);
        }

        final CRLResponseAckMessage crlResponseAckMessage = (new CRLResponseAckMessageBuilder()).caCertificateInfos(caCertificateInfos).cdpsOperationType(CDPSOperationType.PUBLISH)
                .cdpsResponseType(cdpsResponseType).build();
        crlAcknowledgementSender.sendMessage(crlResponseAckMessage);
    }

    /**
     * This method list of CACertificateInfo object using List of CRLInfo
     * 
     * @param crlInfoList
     *            it contains the CACertificateInfo it holds caName and serialNumber and encodedCRL
     * @return List of CACertificateInfo it contains caName and serialNumber
     */
    private List<CACertificateInfo> extractCACertificateInfos(final List<CRLInfo> crlInfoList) {
        if (ValidationUtils.isNullOrEmpty(crlInfoList)) {
            return null;
        }

        final List<CACertificateInfo> caCertificateInfoList = new ArrayList<CACertificateInfo>();

        for (final CRLInfo crlInfo : crlInfoList) {
            caCertificateInfoList.add(crlInfo.getCaCertificateInfo());
        }

        return caCertificateInfoList;
    }

    /**
     * This method logs the DDC error message for each cdpsEntityData object in the List of CRLInfo
     *
     * @param crlInfoList
     *
     * @return List of CACertificateInfo it contains caName and serialNumber
     */
    private void profiledPublishCRLEventFailure(final List<CRLInfo> crlInfoList) {
        try {
            for (CRLInfo crlInfo : crlInfoList) {
                systemRecorder.recordEvent("PKI_CDPS.RECORD_FAILURES", EventLevel.COARSE, "CDPSService", "CDPSService", "[OperationType=PUBLISH, IssuerName="
                        + crlInfo.getCaCertificateInfo().getCaName() + ", SerialNumber=" + crlInfo.getCaCertificateInfo().getCertificateSerialNumber() + ", TimeStamp=" + (new Date()) + "]");
            }
        } catch (Exception exception) {
        logger.error("Error occured while recording the DDC error message", exception.getMessage());
        logger.debug("Error occured while recording the DDC error message ", exception);
        }
    }
}