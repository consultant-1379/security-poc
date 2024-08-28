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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;
import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.CRLEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.CACertificateInfoEventMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers.UnpublishReasonTypeMapper;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.sender.CRLNotificationMessageSender;

@RunWith(MockitoJUnitRunner.class)
public class CRLEventNotificationServiceTest {

    @InjectMocks
    CRLEventNotificationService crlEventNotificationService;

    @Mock
    private CACertificateInfoEventMapper caCertificateInfoEventMapper;

    @Mock
    private CRLNotificationMessageSender crlNotificationMessageSender;

    @Mock
    private UnpublishReasonTypeMapper unpublishReasonTypeMapper;

    @Mock
    private Logger logger;

    @Mock
    private List<CACertificateInfo> caCertificateInfos;

    private List<CACertificateIdentifier> caCertificateIdentifiers;

    /****
     * fireUnpublishEvent(final List<CACertificateIdentifier> caCertificateIdentifiers, final CRLUnpublishType crlUnpublishType)
     */

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {
        caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("TestingCACertificateIdentifire");
        caCertificateIdentifier.setCerficateSerialNumber("123456");
        caCertificateIdentifiers.add(caCertificateIdentifier);

    }

    @Test
    public void testFirePublishEvent() {
        List<CACertificateInfo> caCertificateInfos = new ArrayList<CACertificateInfo>();
        Mockito.when(caCertificateInfoEventMapper.fromModel(caCertificateIdentifiers)).thenReturn(caCertificateInfos);
        crlEventNotificationService.firePublishEvent(caCertificateIdentifiers);
        Mockito.verify(caCertificateInfoEventMapper).fromModel(caCertificateIdentifiers);
    }

    @Test
    public void testFireUnpublishEvent() {
        List<CACertificateInfo> caCertificateInfos = new ArrayList<CACertificateInfo>();
        Mockito.when(caCertificateInfoEventMapper.fromModel(caCertificateIdentifiers)).thenReturn(caCertificateInfos);
        crlEventNotificationService.fireUnpublishEvent(caCertificateIdentifiers);
        Mockito.verify(caCertificateInfoEventMapper, times(1)).fromModel(caCertificateIdentifiers);
    }

    /***
     * crlUnpublishType enum have three elements
     * 
     * 1)USER_INVOKED_REQUEST 2)REVOKED_CA_CERTIFICATE 3)EXPIRED_CA_CERTIFICATE
     * 
     */
    @Test
    public void testFireUnpublishEvent_CRLUnpublishTypeWithNull() {

        when(unpublishReasonTypeMapper.fromModel(CRLUnpublishType.EXPIRED_CA_CERTIFICATE)).thenReturn(null);
        crlEventNotificationService.fireUnpublishEvent(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        Mockito.verify(unpublishReasonTypeMapper, times(1)).fromModel(CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
    }

    /***
     * crlUnpublishType enum have three elements
     * 
     * 1)USER_INVOKED_REQUEST 2)REVOKED_CA_CERTIFICATE 3)EXPIRED_CA_CERTIFICATE
     * 
     */
    @Test
    public void testFireUnpublishEvent_CRLUnpublishType() {
        when(unpublishReasonTypeMapper.fromModel(CRLUnpublishType.EXPIRED_CA_CERTIFICATE)).thenReturn(UnpublishReasonType.EXPIRED_CA_CERTIFICATE);
        when(caCertificateInfoEventMapper.fromModel(caCertificateIdentifiers)).thenReturn(caCertificateInfos);
        crlEventNotificationService.fireUnpublishEvent(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        Mockito.verify(unpublishReasonTypeMapper, times(1)).fromModel(CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        Mockito.verify(caCertificateInfoEventMapper, times(1)).fromModel(caCertificateIdentifiers);
    }
}