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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers;

import java.util.LinkedList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.CRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.CRLEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;

@RunWith(MockitoJUnitRunner.class)
public class CRLUnpublishNotifierTest {

    @InjectMocks
    CRLUnpublishNotifier cRLUnpublishNotifier;

    @Mock
    private CRLEventNotificationService crlEventNotificationService;

    @Mock
    private CRLHelper crlHelper;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    private List<CACertificateIdentifier> caCertificateIdentifiers;
    private List<CACertificateIdentifier> caCertificateIdentifiersEmpty;
    private CRLInfo cRLInfo;
    private List<CRLInfo> cRLinfoList;

    private CRLInfo cRLInfoCDPSStatusFalse;
    private List<CRLInfo> cRLinfoCDPSStatusFalseList;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        caCertificateIdentifiers = CRLSetUpData.getCACertificateIdentifierList();

        cRLInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);

        cRLinfoList = new LinkedList<CRLInfo>();
        cRLinfoList.add(cRLInfo);

        cRLInfoCDPSStatusFalse = CRLSetUpData.getCRLInfo(CRLStatus.LATEST);
        cRLInfoCDPSStatusFalse.setPublishedToCDPS(false);

        cRLinfoCDPSStatusFalseList = new LinkedList<CRLInfo>();
        cRLinfoCDPSStatusFalseList.add(cRLInfoCDPSStatusFalse);

        caCertificateIdentifiersEmpty = new LinkedList<CACertificateIdentifier>();

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeExpired() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeExpired_CANotFoundException() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);
        Mockito.doThrow(CANotFoundException.class).when(crlHelper).updateCRLStatus(cRLInfo);
        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        Mockito.verify(logger, Mockito.times(2)).error("Unable to update CRL from DB for {}", caCertificateIdentifiers.get(0));
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeCDPSSattusFalse() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfoCDPSStatusFalse);

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);

        Mockito.verify(crlHelper, Mockito.atLeastOnce()).updateCRLStatus(cRLInfoCDPSStatusFalse);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeThrowsCANotFoundException() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenThrow(new CANotFoundException());

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
        Mockito.verify(crlEventNotificationService, Mockito.times(0)).fireUnpublishEvent(caCertificateIdentifiersEmpty, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishType() {

        cRLInfo.setPublishedToCDPS(true);
        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.EXPIRED_CA_CERTIFICATE);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeRevoked() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoList);

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

        Mockito.verify(crlHelper).validateCertificateChain(cRLInfo.getIssuerCertificate());
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeRevokedEmptyCRLInfos() {
        cRLInfo.setPublishedToCDPS(true);
        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoList);
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).validateCertificateChain(cRLInfo.getIssuerCertificate());
        Mockito.when(crlHelper.getCANameByCRL(cRLInfo.getId())).thenReturn("ENM_RootCA");

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeCDPSStatusFalseThrowsCRLServiceException() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfoCDPSStatusFalse);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenThrow(new CRLServiceException("Revoked"));
        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

        Mockito.verify(logger).error("Unable to get CRL from DB {} ", new CRLServiceException("Revoked").getMessage());
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeCDPSStatusFalse() {

        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoCDPSStatusFalseList);
        Mockito.when(crlHelper.getCANameByCRL(cRLInfo.getId())).thenReturn("ENM_RootCA");

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);
        Mockito.verify(logger).info("End of notify method in CRLUnpublishNotifier class");
        Mockito.verify(crlEventNotificationService, Mockito.never()).fireUnpublishEvent(caCertificateIdentifiersEmpty, CRLUnpublishType.REVOKED_CA_CERTIFICATE);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeCRLExpired() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.CRL_EXPIRED);

        Mockito.verify(logger).info("End of notify method in CRLUnpublishNotifier class");
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyListOfCACertificateIdentifierCRLUnpublishTypeThrowsRevokedCertificateException() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfo);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoList);
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).validateCertificateChain(cRLInfo.getIssuerCertificate());
        Mockito.when(crlHelper.getCANameByCRL(cRLInfo.getId())).thenReturn("ENM_RootCA");

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyThrowsRevokedCertificateExceptionAndIsPublishedToCDPSFalse() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfoCDPSStatusFalse);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoCDPSStatusFalseList);
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).validateCertificateChain(cRLInfoCDPSStatusFalse.getIssuerCertificate());
        Mockito.when(crlHelper.getCANameByCRL(cRLInfo.getId())).thenReturn("ENM_RootCA");

        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

        Mockito.verify(crlEventNotificationService, Mockito.never()).fireUnpublishEvent(caCertificateIdentifiersEmpty, CRLUnpublishType.REVOKED_CA_CERTIFICATE);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyIsPublishedToCDPSFalseAndThrowsRevokedCertificateException() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfoCDPSStatusFalse);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoCDPSStatusFalseList);
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).validateCertificateChain(cRLInfoCDPSStatusFalse.getIssuerCertificate());
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).updateCRLStatus(cRLInfoCDPSStatusFalse);
        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);

        Mockito.verify(crlEventNotificationService, Mockito.never()).fireUnpublishEvent(caCertificateIdentifiersEmpty, CRLUnpublishType.REVOKED_CA_CERTIFICATE);
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.crlmanagement.notifiers.CRLUnpublishNotifier#notify(java.util.List, com.ericsson.oss.itpf.security.pki.manager.common.crl.CRLUnpublishType)}.
     */
    @Test
    public void testNotifyIsPublishedToCDPSFalseAndThrowsCANotFoundException() {

        Mockito.when(crlHelper.getCRLByCACertificate(caCertificateIdentifiers.get(0), false, false)).thenReturn(cRLInfoCDPSStatusFalse);
        Mockito.when(crlHelper.getAllCRLsWithLatestStatus(CRLStatus.LATEST)).thenReturn(cRLinfoCDPSStatusFalseList);
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).validateCertificateChain(cRLInfoCDPSStatusFalse.getIssuerCertificate());
        Mockito.doThrow(new RevokedCertificateException()).when(crlHelper).updateCRLStatus(cRLInfoCDPSStatusFalse);
        Mockito.doThrow(new CANotFoundException()).when(crlHelper).deleteInvalidCRLs((List<CACertificateIdentifier>) Mockito.any());
        cRLUnpublishNotifier.notify(caCertificateIdentifiers, CRLUnpublishType.REVOKED_CA_CERTIFICATE);
        Mockito.verify(crlEventNotificationService, Mockito.never()).fireUnpublishEvent(caCertificateIdentifiersEmpty, CRLUnpublishType.REVOKED_CA_CERTIFICATE);
    }
}
