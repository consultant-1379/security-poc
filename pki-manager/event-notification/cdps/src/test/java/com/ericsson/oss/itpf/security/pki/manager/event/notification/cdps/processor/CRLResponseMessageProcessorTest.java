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

import static org.mockito.Mockito.times;

import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.event.CRLRequestMessage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.common.model.crl.*;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRL;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl.CRLPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CRLInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender.CRLResponseMessageSender;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.CRLManagementLocalService;

@RunWith(MockitoJUnitRunner.class)
public class CRLResponseMessageProcessorTest {

    @InjectMocks
    CRLResponseMessageProcessor crlResponseMessageProcessor;

    @Mock
    private CACertificateInfoEventMapper caCertificateInfoEventMapper;

    @Mock
    private CRLInfoEventMapper crlInfoEventMapper;

    @Mock
    private CRLResponseMessageSender crlsMessageSender;

    @Mock
    public CRLManagementLocalService crlManagementLocalService;

    @Mock
    private Logger logger;

    @Mock
    private CRLHelper crlHelper;

    @Mock
    private CRLPersistenceHandler crlPersistenceHandler;

    private CRLRequestMessage crlRequestMessage;
    private CACertificateInfo caCertificateInfo;
    private CACertificateIdentifier caCertificateIdentifier;
    private CRLInfo crlInfo;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        crlRequestMessage = new CRLRequestMessage();
        List<CACertificateInfo> caCertificateInfoList = new ArrayList<CACertificateInfo>();
        caCertificateInfo = new CACertificateInfo();
        caCertificateInfo.setCaName("TestingCACertificate");
        caCertificateInfo.setCertificateSerialNumber("123456");
        caCertificateInfoList.add(caCertificateInfo);
        crlRequestMessage.setCaCertificateInfoList(caCertificateInfoList);

        caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("test");
        caCertificateIdentifier.setCerficateSerialNumber("12123");

        crlInfo = new CRLInfo();
        crlInfo.setId(1);
        crlInfo.setPublishedToCDPS(true);
        CRLNumber crlNumber = new CRLNumber();
        crlNumber.setCritical(true);
        crlNumber.setSerialNumber(123456);
        crlInfo.setCrlNumber(crlNumber);
    }

    @Test
    public void process() throws CRLException, FileNotFoundException, java.security.cert.CertificateException {
        crlInfo.setStatus(CRLStatus.LATEST);
        Mockito.when(caCertificateInfoEventMapper.toModel(caCertificateInfo)).thenReturn(caCertificateIdentifier);
        Mockito.when(crlManagementLocalService.getCRLByCACertificateIdentifier(caCertificateIdentifier)).thenReturn(crlInfo);
        CRL crl = new CRL();
        X509CRLHolder x509crlHolder = new X509CRLHolder(getX509CRL("crls/testCA.crl"));
        crl.setX509CRLHolder(x509crlHolder);
        crlInfo.setCrl(crl);
        com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo returnCRLInfo = new com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo();

        Mockito.when(crlInfoEventMapper.fromModel(crlInfo)).thenReturn(returnCRLInfo);
        crlResponseMessageProcessor.process(crlRequestMessage);

        Mockito.verify(caCertificateInfoEventMapper, times(1)).toModel(caCertificateInfo);
        Mockito.verify(crlManagementLocalService, times(1)).getCRLByCACertificateIdentifier(caCertificateIdentifier);
        Mockito.verify(crlInfoEventMapper, times(1)).fromModel(crlInfo);
        Mockito.verify(logger, times(1)).debug("End of process method in CRLResponseMessageProcessor class");

    }

    @Test
    public void process_CRLStatus_INVALID() throws CRLException, FileNotFoundException, java.security.cert.CertificateException {
        crlInfo.setStatus(CRLStatus.INVALID);
        Mockito.when(caCertificateInfoEventMapper.toModel(caCertificateInfo)).thenReturn(caCertificateIdentifier);
        Mockito.when(crlManagementLocalService.getCRLByCACertificateIdentifier(caCertificateIdentifier)).thenReturn(crlInfo);
        CRL crl = new CRL();
        X509CRLHolder x509crlHolder = new X509CRLHolder(getX509CRL("crls/testCA.crl"));
        crl.setX509CRLHolder(x509crlHolder);
        crlInfo.setCrl(crl);
        com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo returnCRLInfo = new com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo();

        Mockito.when(crlInfoEventMapper.fromModel(crlInfo)).thenReturn(returnCRLInfo);
        crlResponseMessageProcessor.process(crlRequestMessage);
        Mockito.verify(caCertificateInfoEventMapper, times(1)).toModel(caCertificateInfo);
        Mockito.verify(crlManagementLocalService, times(1)).getCRLByCACertificateIdentifier(caCertificateIdentifier);
        Mockito.verify(crlInfoEventMapper, times(1)).fromModel(crlInfo);
        Mockito.verify(logger, times(1)).debug("End of process method in CRLResponseMessageProcessor class");
    }

    @Test
    public void process_CRLStatus_EXPIRED() throws CRLException, FileNotFoundException, java.security.cert.CertificateException {
        crlInfo.setStatus(CRLStatus.EXPIRED);
        Mockito.when(caCertificateInfoEventMapper.toModel(caCertificateInfo)).thenReturn(caCertificateIdentifier);
        Mockito.when(crlManagementLocalService.getCRLByCACertificateIdentifier(caCertificateIdentifier)).thenReturn(crlInfo);
        CRL crl = new CRL();
        X509CRLHolder x509crlHolder = new X509CRLHolder(getX509CRL("crls/testCA.crl"));
        crl.setX509CRLHolder(x509crlHolder);
        crlInfo.setCrl(crl);
        com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo returnCRLInfo = new com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo();

        Mockito.when(crlInfoEventMapper.fromModel(crlInfo)).thenReturn(returnCRLInfo);
        crlResponseMessageProcessor.process(crlRequestMessage);
        Mockito.verify(caCertificateInfoEventMapper, times(1)).toModel(caCertificateInfo);
        Mockito.verify(crlManagementLocalService, times(1)).getCRLByCACertificateIdentifier(caCertificateIdentifier);
        Mockito.verify(crlInfoEventMapper, times(1)).fromModel(crlInfo);
        Mockito.verify(logger, times(1)).debug("End of process method in CRLResponseMessageProcessor class");
    }

    private X509CRL getX509CRL(String fileName) throws FileNotFoundException, CRLException, java.security.cert.CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(fileName);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        X509CRL x509crl = (X509CRL) certificateFactory.generateCRL(inputStream);
        return x509crl;
    }
}
