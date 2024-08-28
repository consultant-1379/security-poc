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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSResponse;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.instrumentation.TDPSInstrumentationBean;
import com.ericsson.oss.itpf.security.pki.ra.tdps.event.notification.sender.TDPSAcknowledgementEventSender;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.eserviceref.TDPSLocalEServiceHolder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.local.service.api.TDPSLocalService;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

/**
 * 
 * @author tcsasma
 *
 */

@RunWith(MockitoJUnitRunner.class)
public class PublishTDPSCertificateEventTest {

    @InjectMocks
    PublishTDPSCertificateEvent publishTDPSCertificateEvent;

    @InjectMocks
    TDPSLocalEServiceHolder eServiceHolder;

    @Mock
    TDPSLocalService tdpsLocalService;

    @Mock
    TDPSEntityDataMapper tDPSEntityDataMapper;

    @Mock
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Mock
    TDPSResponseMapper tDPSResponseMapper;

    @Mock
    TDPSEntityData tdpsEntityData;

    @Mock
    TDPSAcknowledgementEventSender tdpsAcknowledgementEventSender;

    @Mock
    TDPSCertificateStatusMapper tdpsCertificateStatusMapper;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    TDPSInstrumentationBean tdpsInstrumentationBean;

    private TDPSCertificateEvent tDPSCertificateEvent;
    private TDPSCertificateInfo tdpsCertificateInfo;

    @Test
    public void testExecute() throws CertificateEncodingException {
        setupDataExecute();

        publishTDPSCertificateEvent.execute(tDPSCertificateEvent);
        eServiceHolder.getTDPSLocalService().publishTDPSCertificates(tdpsCertificateInfo);
        Mockito.verify(tdpsLocalService).publishTDPSCertificates(Matchers.<TDPSCertificateInfo> anyObject());

    }

    @Test
    public void testExecuteTDPSEntityDataNotNull() throws CertificateEncodingException {

        setupDataExecute();

        publishTDPSCertificateEvent.execute(tDPSCertificateEvent);
        Mockito.verify(tdpsAcknowledgementEventSender).send(Matchers.<TDPSAcknowledgementEvent> anyObject());

    }

    @Test
    public void testExecuteTrustDistributionServiceException() throws CertificateEncodingException {
        setupDataExecute();
        Mockito.doThrow(TrustDistributionServiceException.class).when(tdpsLocalService).publishTDPSCertificates(Matchers.<TDPSCertificateInfo> anyObject());

        publishTDPSCertificateEvent.execute(tDPSCertificateEvent);
        Mockito.verify(logger).error("Certificates couldn't be published for entityName {} of type {}, to TDPS", tdpsCertificateInfo.getEntityName(), tdpsCertificateInfo.getTdpsEntityType());

    }

    @Test
    public void testExecuteForSuccessResponse() throws CertificateException, FileNotFoundException {

        setupDataExecute();

        tdpsCertificateInfo.setEncodedCertificate(getTDPSCerts());

        Mockito.when(tDPSResponseMapper.toModel(TDPSResponse.SUCCESS)).thenReturn(TDPSResponseType.SUCCESS);

        publishTDPSCertificateEvent.execute(tDPSCertificateEvent);
        eServiceHolder.getTDPSLocalService().publishTDPSCertificates(tdpsCertificateInfo);
        Mockito.verify(tdpsLocalService).publishTDPSCertificates(Matchers.<TDPSCertificateInfo> anyObject());

    }

    public byte[] getTDPSCerts() throws CertificateException, FileNotFoundException {

        Certificate tDPSCert = getCertificate();
        return tDPSCert.getEncoded();
    }

    private Certificate getCertificate() {

        String tDPSCertPath = PublishTDPSCertificateEventTest.class.getResource("/Certificates/verifyDigiSignature_vendorCerts/factory.crt").getPath();

        FileInputStream fileInputStream;
        Certificate tDPSCert = null;
        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            fileInputStream = new FileInputStream(tDPSCertPath);
            tDPSCert = certificateFactory.generateCertificate(fileInputStream);
        } catch (FileNotFoundException | CertificateException exception) {
            logger.error("Error Occured:" + exception.getMessage());

        }

        return tDPSCert;
    }

    public void setupDataExecute() throws CertificateEncodingException {
        byte[] encodedCertificate = getCertificate().getEncoded();
        tDPSCertificateEvent = new TDPSCertificateEvent();
        tdpsCertificateInfo = new TDPSCertificateInfo();
        List<TDPSCertificateInfo> listTDPSCertificateInfo = new ArrayList<TDPSCertificateInfo>();
        listTDPSCertificateInfo.add(tdpsCertificateInfo);

        tdpsCertificateInfo.setEntityName("ENTITY");
        tdpsCertificateInfo.setSerialNumber("123432534");
        TDPSEntityType tdpsEntityType = TDPSEntityType.ENTITY;
        tdpsCertificateInfo.setTdpsEntityType(tdpsEntityType);
        tDPSCertificateEvent.setTdpsCertificateInfos(listTDPSCertificateInfo);
        tdpsCertificateInfo.setEncodedCertificate(encodedCertificate);
    }
}
