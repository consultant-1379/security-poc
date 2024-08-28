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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.processor;

import java.util.ArrayList;

import java.util.List;

import javax.ejb.EJB;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.builders.CRLResponseMessageBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CRLInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender.CRLResponseMessageSender;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementLocalService;

/**
 * CRLResponseMessageProcessor class prepares a CRL Request Message and send it to the CDPS over a ClusteredCRLResponseChannel.
 * 
 * @author xjagcho
 * 
 */
public class CRLResponseMessageProcessor {

    @Inject
    private CACertificateInfoEventMapper caCertificateInfoEventMapper;

    @Inject
    private CRLInfoEventMapper crlInfoEventMapper;

    @Inject
    private CRLResponseMessageSender crlsMessageSender;

    @EJB
    public CRLManagementLocalService crlManagementLocalService;

    @Inject
    private Logger logger;

    /**
     * This method process the CRL Request Message and send it to the CDPS
     * 
     * @param crlRequestMessage
     *            it holds CACertificateInfo it contains caName and certificate serial number
     */
    public void process(final CRLRequestMessage crlRequestMessage) {
        logger.debug("process method in CRLResponseMessageProcessor class");

        processMessage(crlRequestMessage);

        logger.debug("End of process method in CRLResponseMessageProcessor class");
    }

    /**
     * This method process the CRL Request Message and send it to the CDPS over a ClusteredCRLResponseChannel
     * 
     * @param crlRequestMessage
     *            it holds CACertificateInfo it contains caName and certificate serial number
     */
    private void processMessage(final CRLRequestMessage crlRequestMessage) {
        logger.debug("processMessage method in CRLResponseMessageProcessor class");

        final List<CRLInfo> crlInfos = new ArrayList<CRLInfo>();

        for (CACertificateInfo caCertificateInfo : crlRequestMessage.getCaCertificateInfoList()) {
            final CACertificateIdentifier caCertificateIdentifier = caCertificateInfoEventMapper.toModel(caCertificateInfo);

            final com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo crlInfoModel;
            crlInfoModel = crlManagementLocalService.getCRLByCACertificateIdentifier(caCertificateIdentifier);

            final CRLInfo crlInfoData = crlInfoEventMapper.fromModel(crlInfoModel);
            crlInfoData.setCaCertificateInfo(caCertificateInfo);

            crlInfos.add(crlInfoData);
        }

        final CRLResponseMessage crlMessage = (new CRLResponseMessageBuilder()).crlInfos(crlInfos).build();
        crlsMessageSender.sendMessage(crlMessage);

        logger.debug("End of processMessage method in CRLResponseMessageProcessor class");
    }
}
