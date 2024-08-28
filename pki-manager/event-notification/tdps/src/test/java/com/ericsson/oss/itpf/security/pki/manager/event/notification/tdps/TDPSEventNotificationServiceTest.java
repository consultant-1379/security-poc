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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.TDPSPublishStatusType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.TDPSEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers.*;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.sender.TDPSCertificateEventSender;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.*;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSEventNotificationServiceTest {

    @InjectMocks
    TDPSEventNotificationService tDPSEventNotificationService;

    @Mock
    Certificate certificate;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    CertificateAuthority certificateAuthority;

    @Mock
    TDPSEntityTypeMapper tdpsEntityTypeMapper;

    @Mock
    TDPSCertificateStatusTypeMapper tDPSCertificateStatusTypeMapper;

    @Mock
    TDPSOperationTypeMapper tdpsOperationTypeMapper;

    @Mock
    TDPSCertificateEvent tdpsCertificateEvent;

    @Mock
    TDPSCertificateEventSender tdpsCertificateEventSender;

    private static String entityName = "entityName";
    private static String serialNumber = "1";
    private static String issuerName = "issuerName";
    private static byte[] encoded = new byte[] { 1 };
    private static CertificateStatus certificateStatus = CertificateStatus.ACTIVE;
    private static TDPSPublishStatusType tDPSPublishStatusType = TDPSPublishStatusType.PUBLISH;

    private static List<Certificate> certificates = new ArrayList<Certificate>();

    @Test
    public void testFireCertificateEventNotification() throws CertificateEncodingException {

        setupData();
        tDPSEventNotificationService.fireCertificateEvent(EntityType.ENTITY, entityName, tDPSPublishStatusType, certificates);


        Mockito.verify(tdpsCertificateEventSender).send(Mockito.<TDPSCertificateEvent> anyObject());

    }

    @Test
    public void testFireCertificateEventNotificationEntityType() throws CertificateEncodingException {

        setupData();

        tDPSEventNotificationService.fireCertificateEvent(null, entityName, tDPSPublishStatusType, certificates);

    }

    @Test
    public void testFireCertificateEventNotificationEntityTypeEntityName() throws CertificateEncodingException {

        setupData();

        tDPSEventNotificationService.fireCertificateEvent(EntityType.ENTITY, null, tDPSPublishStatusType, certificates);
    }

    @Test
    public void testFireCertificateEventNotificationStatus() throws CertificateEncodingException {

        setupData();

        tDPSEventNotificationService.fireCertificateEvent(EntityType.ENTITY, entityName, null, certificates);
    }

    @Test
    public void testFireCertificateEventNotificationCertificates() throws CertificateEncodingException {

        setupData();

        tDPSEventNotificationService.fireCertificateEvent(EntityType.ENTITY, entityName, tDPSPublishStatusType, null);
    }

    public void setupData() throws CertificateEncodingException {

        certificates.add(certificate);

        Mockito.when(certificate.getX509Certificate()).thenReturn(x509Certificate);
        Mockito.when(certificate.getX509Certificate().getEncoded()).thenReturn(encoded);
        Mockito.when(certificate.getSerialNumber()).thenReturn(serialNumber);
        Mockito.when(certificate.getStatus()).thenReturn(certificateStatus);

        Mockito.when(certificate.getIssuer()).thenReturn(certificateAuthority);
        Mockito.when(certificate.getIssuer().getName()).thenReturn(issuerName);
        Mockito.when(tdpsEntityTypeMapper.toModel(EntityType.ENTITY)).thenReturn(TDPSEntityType.ENTITY);
        Mockito.when(tDPSCertificateStatusTypeMapper.toModel(certificateStatus)).thenReturn(TDPSCertificateStatusType.ACTIVE);
        Mockito.when(tdpsOperationTypeMapper.toModel(TDPSPublishStatusType.PUBLISH)).thenReturn(TDPSOperationType.PUBLISH);

    }

}
