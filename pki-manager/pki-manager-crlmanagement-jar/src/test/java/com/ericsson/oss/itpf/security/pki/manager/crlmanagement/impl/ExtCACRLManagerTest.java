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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.persistence.PersistenceException;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.helper.CRLDownloader;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ CRLDownloader.class, X509CRLHolder.class })
public class ExtCACRLManagerTest {
    @InjectMocks
    ExtCACRLManager extCACRLManager;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    private static SetUPData setUPData;
    private static ExternalCRLInfo externalCRLInfo;
    private static ExternalCRLInfo externalCRLInfo2;
    private static CAEntityData cAEntityData;

    @BeforeClass
    public static void setUpBeforeClass() throws CertificateException, IOException {
        setUPData = new SetUPData();

        externalCRLInfo = setUPData.getExternalCRLInfo("crls/testCA.crl");
        externalCRLInfo2 = setUPData.getExternalCRLInfo("crls/crca2048.crl");
        cAEntityData = CRLSetUpData.getCAEntityData();
    }

    @Test
    public void addCRLTest() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "External_CA_1", "certificateAuthorityData.name")).thenReturn(null);
        Mockito.doNothing().when(caPersistenceHelper).addCRL("External_CA_1", externalCRLInfo);

        extCACRLManager.addCRL("External_CA_1", externalCRLInfo);

        Mockito.verify(caPersistenceHelper).addCRL("External_CA_1", externalCRLInfo);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void addCRLWithEmptyCRLTest() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {
        extCACRLManager.addCRL("External_CA_1", null);
    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void addCRLPersistencyErrorTest() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {
        Mockito.doThrow(PersistenceException.class).when(caPersistenceHelper).addCRL("External_CA_1", externalCRLInfo);

        extCACRLManager.addCRL("External_CA_1", externalCRLInfo);
    }

    @Test
    public void configCRLInfoTest() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {
        Mockito.doNothing().when(caPersistenceHelper).configCRLInfo("External_CA_1", true, 10000);

        extCACRLManager.configCRLInfo("External_CA_1", true, 10000);
    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void configCRLInfoInternalErrorTest() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {
        Mockito.doThrow(PersistenceException.class).when(caPersistenceHelper).configCRLInfo("External_CA_1", true, 10000);

        extCACRLManager.configCRLInfo("External_CA_1", true, 10000);
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void listExternalCRLInfoTestCANotFound() {
        Mockito.when(caPersistenceHelper.getExternalCRLInfoForExtCA("CA_NOT_EXIST")).thenThrow(new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND));
        extCACRLManager.listExternalCRLInfo("CA_NOT_EXIST");
    }

    @Test(expected = ExternalCRLNotFoundException.class)
    public void listExternalCRLInfoTestCAWithoutCRL() {
        Mockito.when(caPersistenceHelper.getExternalCRLInfoForExtCA("CA_WITHOUT_CRL")).thenReturn(null);
        extCACRLManager.listExternalCRLInfo("CA_WITHOUT_CRL");
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void listExternalCRLInfoTestInternalError() {
        Mockito.when(caPersistenceHelper.getExternalCRLInfoForExtCA("A_CA")).thenThrow(Exception.class);
        extCACRLManager.listExternalCRLInfo("A_CA");
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void listExternalCRLInfoTestEmptyParameterError() {
        extCACRLManager.listExternalCRLInfo("");
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void listExternalCRLInfoTestNullParameterError() {
        extCACRLManager.listExternalCRLInfo(null);
    }

    @Test
    public void listExternalCRLInfoTest() {
        final List<ExternalCRLInfo> crlInfoList_test = new ArrayList<ExternalCRLInfo>();
        crlInfoList_test.add(externalCRLInfo);

        Mockito.when(caPersistenceHelper.getExternalCRLInfoForExtCA("External_CA_1")).thenReturn(crlInfoList_test);

        final List<ExternalCRLInfo> crlInfoList = extCACRLManager.listExternalCRLInfo("External_CA_1");
        Assert.assertTrue(crlInfoList.size() == 1);

    }

    @Test
    public void listExternalCRLInfoTestExc() {
        final List<ExternalCRLInfo> crlInfoList_test = new ArrayList<ExternalCRLInfo>();
        crlInfoList_test.add(externalCRLInfo);

        Mockito.when(caPersistenceHelper.getExternalCRLInfoForExtCA("External_CA_1")).thenReturn(crlInfoList_test);

        final List<ExternalCRLInfo> crlInfoList = extCACRLManager.listExternalCRLInfo("External_CA_1");
        Assert.assertTrue(crlInfoList.size() == 1);

    }

    @Test
    public void removeCrlsTest() {
        Mockito.when(caPersistenceHelper.getCAEntity("External_CA_1")).thenReturn(cAEntityData);
        extCACRLManager.removeAllCRLs("External_CA_1");
        Mockito.verify(caPersistenceHelper).getCAEntity("External_CA_1");
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void removeCrlsExtCANotFoundTest() {
        Mockito.when(caPersistenceHelper.getCAEntity("EXT_CA_NOT_EXIST")).thenThrow(new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND));
        extCACRLManager.removeAllCRLs("EXT_CA_NOT_EXIST");
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void removeCrlsExtCAExistAsCATest() {
        final CAEntityData mockedCaEntity = new CAEntityData();
        mockedCaEntity.setExternalCA(false);
        Mockito.when(caPersistenceHelper.getCAEntity("EXIST_AS_CA")).thenReturn(mockedCaEntity);

        extCACRLManager.removeAllCRLs("EXIST_AS_CA");
    }

    @SuppressWarnings("unchecked")
    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void removeCrlsExtCAPersistenceExceptionTest() {

        Mockito.when(caPersistenceHelper.getCAEntity("EXT_CA")).thenThrow(PersistenceException.class);

        extCACRLManager.removeAllCRLs("EXT_CA");
    }

    @Test(expected = ExternalCAInUseException.class)
    public void removeCrlsExtCAUsedInTrustTest() {
        final CAEntityData mockedExtCaEntity = new CAEntityData();
        mockedExtCaEntity.setExternalCA(true);
        Mockito.when(caPersistenceHelper.getCAEntity("EXT_CA")).thenReturn(mockedExtCaEntity);
        final List<String> mockedTrustNames = new ArrayList<String>();
        mockedTrustNames.add("A TRUST");
        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(mockedExtCaEntity)).thenReturn(mockedTrustNames);

        extCACRLManager.removeAllCRLs("EXT_CA");
    }

    @Test
    public void removeCrlsExtCAUsedInTrustTest2() {

        final ExternalCRLInfoData mockedAssociatedExternalCRLInfoData = new ExternalCRLInfoData();
        mockedAssociatedExternalCRLInfoData.setId(1);
        final CertificateAuthorityData mockedAssociatedcertificateAuthorityData = new CertificateAuthorityData();
        mockedAssociatedcertificateAuthorityData.setExternalCrlInfoData(mockedAssociatedExternalCRLInfoData);

        final CAEntityData mockedAssociatedExtCAEntity = new CAEntityData();
        mockedAssociatedExtCAEntity.setCertificateAuthorityData(mockedAssociatedcertificateAuthorityData);
        mockedAssociatedExtCAEntity.setExternalCA(true);
        final Set<CAEntityData> associatedList = new HashSet<CAEntityData>();
        associatedList.add(mockedAssociatedExtCAEntity);

        final ExternalCRLInfoData mockedExternalCRLInfoData = new ExternalCRLInfoData();
        mockedExternalCRLInfoData.setId(2);

        final CertificateAuthorityData mockedCertificateAuthorityData = new CertificateAuthorityData();
        mockedCertificateAuthorityData.setExternalCrlInfoData(mockedExternalCRLInfoData);

        final CAEntityData mockedExtCaEntity = new CAEntityData();
        mockedExtCaEntity.setExternalCA(true);
        mockedExtCaEntity.setAssociated(associatedList);
        mockedExtCaEntity.setCertificateAuthorityData(mockedCertificateAuthorityData);

        Mockito.when(caPersistenceHelper.getCAEntity("EXT_CA")).thenReturn(mockedExtCaEntity);
        final List<String> mockedTrustNames = new ArrayList<String>();
        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(mockedExtCaEntity)).thenReturn(mockedTrustNames);

        extCACRLManager.removeAllCRLs("EXT_CA");

        Mockito.verify(caPersistenceHelper).updateExtCA(mockedExtCaEntity);
        Mockito.verify(caPersistenceHelper).deleteExtCA(mockedAssociatedExtCAEntity);
        Mockito.verify(caPersistenceHelper).deleteExternalCRLInfo(mockedExternalCRLInfoData);
        Mockito.verify(caPersistenceHelper).deleteExternalCRLInfo(mockedAssociatedExternalCRLInfoData);
    }

    private CAEntityData getMockedCAEntityData(boolean fillRoot) {

        // fill ExternalCRTInfo associated
        final ExternalCRLInfoData mockedAssociatedExternalCRLInfoData = new ExternalCRLInfoData();
        mockedAssociatedExternalCRLInfoData.setId(2);
        if (!fillRoot) {
            mockedAssociatedExternalCRLInfoData.setCrl(externalCRLInfo.getX509CRL().getCrlBytes());
        }

        final CertificateAuthorityData mockedAssociatedcertificateAuthorityData = new CertificateAuthorityData();
        mockedAssociatedcertificateAuthorityData.setExternalCrlInfoData(mockedAssociatedExternalCRLInfoData);

        final CAEntityData mockedAssociatedExtCAEntity = new CAEntityData();
        mockedAssociatedExtCAEntity.setCertificateAuthorityData(mockedAssociatedcertificateAuthorityData);
        mockedAssociatedExtCAEntity.setExternalCA(true);
        final Set<CAEntityData> associatedList = new HashSet<CAEntityData>();
        associatedList.add(mockedAssociatedExtCAEntity);

        // fills ExternalCRTInfo Root CA
        final ExternalCRLInfoData mockedExternalCRLInfoData = new ExternalCRLInfoData();
        mockedExternalCRLInfoData.setId(1);

        if (fillRoot) {
            mockedExternalCRLInfoData.setCrl(externalCRLInfo.getX509CRL().getCrlBytes());
        }

        // creates ExtCAEntity Root

        final CertificateAuthorityData mockedCertificateAuthorityData = new CertificateAuthorityData();
        mockedCertificateAuthorityData.setExternalCrlInfoData(mockedExternalCRLInfoData);

        final CAEntityData mockedExtCaEntity = new CAEntityData();
        mockedExtCaEntity.setExternalCA(true);
        mockedExtCaEntity.setAssociated(associatedList);
        mockedExtCaEntity.setCertificateAuthorityData(mockedCertificateAuthorityData);

        return mockedExtCaEntity;
    }

    @Test
    public void removeCrlsWithIssuerNameRoot() {
        final CAEntityData mockedExtCaEntity = getMockedCAEntityData(true);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA_1")).thenReturn(mockedExtCaEntity);

        extCACRLManager.removeCRLs("External_CA_1", "CN=testCA");
    }

    @Test
    public void removeCrlsWithIssuerNameAssociated() {
        final CAEntityData mockedExtCaEntity = getMockedCAEntityData(false);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA_1")).thenReturn(mockedExtCaEntity);

        extCACRLManager.removeCRLs("External_CA_1", "CN=testCA");
    }

    @Test
    public void removeCrlsWithoutIssuerName() {

        final CAEntityData mockedExtCaEntity = getMockedCAEntityData(false);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA_1")).thenReturn(mockedExtCaEntity);

        extCACRLManager.removeCRLs("External_CA_1", null);
    }

    @Test
    public void autoUpdateExpiredCRLsPersistencyErrorTest() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {
        Mockito.doThrow(PersistenceException.class).when(caPersistenceHelper).getExpiredCRLs(Mockito.any(Date.class));

        extCACRLManager.autoUpdateExpiredCRLs();
        Mockito.verify(systemRecorder).recordSecurityEvent(Mockito.eq("PKIMANAGER-CRLMANAGEMENT"), Mockito.eq("PKIMANAGER-CRLMANAGEMENT.INTERNAL_ERRROR"), Mockito.any(String.class),
                Mockito.eq("PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE"), Mockito.eq(ErrorSeverity.CRITICAL), Mockito.eq("FAILURE"));
    }

    @Test
    public void autoUpdateExpiredCRLsPersistencyError2Test() throws CRLException, MalformedURLException {

        Mockito.doThrow(PersistenceException.class).when(caPersistenceHelper).setExpiredCRLs(Mockito.any(ExternalCRLInfoData.class));

        final String url = "http://localhost";
        final List<ExternalCRLInfoData> externalCRLInfoDataList = prepareForautoUpdateExpiredCRLs(url);

        Mockito.when(caPersistenceHelper.getExpiredCRLs(Mockito.any(Date.class))).thenReturn(externalCRLInfoDataList);
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(Mockito.any(URL.class))).thenReturn(externalCRLInfo.getX509CRL().retrieveCRL());
        extCACRLManager.autoUpdateExpiredCRLs();

    }

    @SuppressWarnings("unchecked")
    @Test
    public void autoUpdateExpiredCRLCRLExceptionTest() throws CRLException, MalformedURLException {
        final String url = "http://localhost";

        final List<ExternalCRLInfoData> externalCRLInfoDataList = prepareForautoUpdateExpiredCRLs(url);

        Mockito.when(caPersistenceHelper.getExpiredCRLs(Mockito.any(Date.class))).thenReturn(externalCRLInfoDataList);
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(Mockito.any(URL.class))).thenThrow(CRLException.class);
        extCACRLManager.autoUpdateExpiredCRLs();
        Mockito.verify(systemRecorder).recordSecurityEvent(Mockito.eq("PKIMANAGER-CRLMANAGEMENT"), Mockito.eq("PKIMANAGER-CRLMANAGEMENT.PARSING"), Mockito.any(String.class),
                Mockito.eq("PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE"), Mockito.eq(ErrorSeverity.CRITICAL), Mockito.eq("FAILURE"));
    }

    @SuppressWarnings("unchecked")
    @Test
    public void autoUpdateExpiredCRLIOExceptionTest() throws Exception {
        final String url = "http://localhost";

        final List<ExternalCRLInfoData> externalCRLInfoDataList = prepareForautoUpdateExpiredCRLs(url);

        Mockito.when(caPersistenceHelper.getExpiredCRLs(Mockito.any(Date.class))).thenReturn(externalCRLInfoDataList);
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(Mockito.any(URL.class))).thenThrow(IOException.class);
        extCACRLManager.autoUpdateExpiredCRLs();
        Mockito.verify(systemRecorder).recordSecurityEvent(Mockito.eq("PKIMANAGER-CRLMANAGEMENT"), Mockito.eq("PKIMANAGER-CRLMANAGEMENT.INTERNAL_ERRROR"), Mockito.anyString(),
                Mockito.eq("PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE"), Mockito.eq(ErrorSeverity.CRITICAL), Mockito.eq("FAILURE"));
    }

    @Test
    public void autoUpdateExpiredCRLMalformedURLExceptionTest() throws CRLException, MalformedURLException {
        final String url = "ht tp://localhost";

        final List<ExternalCRLInfoData> externalCRLInfoDataList = prepareForautoUpdateExpiredCRLs(url);

        Mockito.when(caPersistenceHelper.getExpiredCRLs(Mockito.any(Date.class))).thenReturn(externalCRLInfoDataList);
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(Mockito.any(URL.class))).thenReturn(externalCRLInfo.getX509CRL().retrieveCRL());
        extCACRLManager.autoUpdateExpiredCRLs();
        Mockito.verify(systemRecorder).recordSecurityEvent(Mockito.eq("PKIMANAGER-CRLMANAGEMENT"), Mockito.eq("PKIMANAGER-CRLMANAGEMENT.MALFORMEDURL"), Mockito.anyString(),
                Mockito.eq("PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE"), Mockito.eq(ErrorSeverity.CRITICAL), Mockito.eq("FAILURE"));
    }

    @Test
    public void autoUpdateExpiredCRLsTest() throws MalformedURLException, CRLException {
        final String url = "http://localhost";

        final List<ExternalCRLInfoData> externalCRLInfoDataList = prepareForautoUpdateExpiredCRLs(url);

        Mockito.when(caPersistenceHelper.getExpiredCRLs(Mockito.any(Date.class))).thenReturn(externalCRLInfoDataList);
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(Mockito.any(URL.class))).thenReturn(externalCRLInfo.getX509CRL().retrieveCRL());
        extCACRLManager.autoUpdateExpiredCRLs();
    }

    @Test
    public void autoUpdateExpiredCRLsWrongIssuerTest() throws MalformedURLException, CRLException {
        final String url = "http://localhost";

        final List<ExternalCRLInfoData> externalCRLInfoDataList = prepareForautoUpdateExpiredCRLs(url);

        Mockito.when(caPersistenceHelper.getExpiredCRLs(Mockito.any(Date.class))).thenReturn(externalCRLInfoDataList);
        PowerMockito.mockStatic(CRLDownloader.class);
        PowerMockito.when(CRLDownloader.getCRLFromURL(Mockito.any(URL.class))).thenReturn(externalCRLInfo2.getX509CRL().retrieveCRL());
        extCACRLManager.autoUpdateExpiredCRLs();
        Mockito.verify(systemRecorder).recordSecurityEvent(Mockito.eq("PKIMANAGER-CRLMANAGEMENT"), Mockito.eq("PKIMANAGER-CRLMANAGEMENT.MISMATCH"), Mockito.anyString(),
                Mockito.eq("PKIMANAGER-CRLMANAGEMENT.AUTOCRLUPDATE"), Mockito.eq(ErrorSeverity.CRITICAL), Mockito.eq("FAILURE"));
    }

    /**
     * @param url
     * @return
     */
    private List<ExternalCRLInfoData> prepareForautoUpdateExpiredCRLs(final String url) {
        final List<ExternalCRLInfoData> externalCRLInfoDataList = new ArrayList<ExternalCRLInfoData>();

        final ExternalCRLInfoData externalCRLInfoData = new ExternalCRLInfoData();
        externalCRLInfoData.setAutoUpdate(true);
        externalCRLInfoData.setAutoUpdateCheckTimer(2);
        externalCRLInfoData.setCrl(externalCRLInfo.getX509CRL().getCrlBytes());
        externalCRLInfoData.setNextUpdate(new Date());
        externalCRLInfoData.setUpdateUrl(url);

        externalCRLInfoDataList.add(externalCRLInfoData);
        return externalCRLInfoDataList;
    }
}
