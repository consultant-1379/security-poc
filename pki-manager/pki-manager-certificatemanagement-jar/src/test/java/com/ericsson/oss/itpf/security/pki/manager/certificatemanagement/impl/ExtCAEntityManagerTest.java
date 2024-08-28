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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateNotYetValidException;
import java.util.ArrayList;
import java.util.Arrays;
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
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCACRLsExistException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;

@RunWith(MockitoJUnitRunner.class)
public class ExtCAEntityManagerTest {
    @InjectMocks
    ExtCAEntityManager extCAEntityManager;

    @InjectMocks
    ExtCAEntityManager extCAEntityManagerMock;

    @Mock
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    SystemRecorder systemRecorder;

    private static SetUPData setUPData;
    private static X509Certificate x509Certificate;
    private static X509Certificate x509CertificateNew;
    private static X509Certificate x509Certificate_NotYetValid;
    private static X509Certificate x509CertificateSubKeyIdAsNull;
    private static X509Certificate x509CertificateAuthKeyIdAsNull;
    private static X509Certificate valid_x509Certificate;

    @BeforeClass
    public static void setUpBeforeClass() {
        setUPData = new SetUPData();
        try {
            x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");
            x509CertificateNew = setUPData.getX509Certificate("certificates/RootCANew.crt");
            x509Certificate_NotYetValid = setUPData.getX509Certificate("certificates/NotValidCert.pem");
            x509CertificateSubKeyIdAsNull = setUPData.getX509Certificate("certificates/SubjectKeyIdentifierAsNullInCert.crt");
            x509CertificateAuthKeyIdAsNull = setUPData.getX509Certificate("certificates/AuthorityKeyIdentifierAsNullInCert.crt");
            valid_x509Certificate = setUPData.getX509Certificate("certificates/PrimeTowerRootCA.crt");
        } catch (CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }

    @SuppressWarnings("unchecked")
    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void importCertificate_ExternalCredentialMgmtServiceException() throws ExternalCAAlreadyExistsException, CertificateFieldException, ExternalCredentialMgmtServiceException,
            CertificateAlreadyExistsException, PersistenceException, CertificateException, IOException {
        final List<CertificateData> certificateList = new ArrayList<CertificateData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateList));
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "External_CA_1", "certificateAuthorityData.name")).thenReturn(null);
        Mockito.doNothing().when(persistenceManager).createEntity(Mockito.any(Class.class));
        Mockito.when(persistenceManager.updateEntity(Mockito.any(CAEntityData.class))).thenReturn(null);
        Mockito.doThrow(new PersistenceException()).when(caPersistenceHelper).storeExtCACertificate(Mockito.anyString(), (Certificate) Mockito.anyObject(), Mockito.anyBoolean());
        extCAEntityManager.importCertificate("External_CA_1", x509CertificateNew, false);

    }

    @SuppressWarnings("unchecked")
    @Test
    public void importCertificate() throws ExternalCAAlreadyExistsException, CertificateFieldException, ExternalCredentialMgmtServiceException, CertificateAlreadyExistsException {
        final List<CertificateData> certificateList = new ArrayList<CertificateData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateList));
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "External_CA_1", "certificateAuthorityData.name")).thenReturn(null);
        Mockito.doNothing().when(persistenceManager).createEntity(Mockito.any(Class.class));
        Mockito.when(persistenceManager.updateEntity(Mockito.any(CAEntityData.class))).thenReturn(null);
        extCAEntityManager.importCertificate("External_CA_1", x509CertificateNew, false);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void importCertificate_MissingExtCAName() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException, ExternalCAAlreadyExistsException,
            ExternalCredentialMgmtServiceException {

        extCAEntityManager.importCertificate("", x509Certificate, false);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void importCertificate_MissingCertificate() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException, ExternalCAAlreadyExistsException,
            ExternalCredentialMgmtServiceException {

        extCAEntityManager.importCertificate("External_CA_1", null, false);
    }

    @Test(expected = ExpiredCertificateException.class)
    public void importCertificate_ExpiredCertificate() throws ExpiredCertificateException {

        extCAEntityManager.importCertificate("External_CA_1", x509Certificate, false);
    }

    @Test(expected = ExpiredCertificateException.class)
    public void importCertificate_SubjectKeyIdentifierNull() throws ExpiredCertificateException {

        extCAEntityManager.importCertificate("External_CA_1", x509Certificate, false);
    }

    @Test(expected = ExpiredCertificateException.class)
    public void importCertificate_CertificateNotYetValid() throws CertificateNotYetValidException {

        extCAEntityManager.importCertificate("External_CA_1", x509Certificate_NotYetValid, false);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void importCertificate_SubjectKeyIdentifier_Null() throws CertificateNotYetValidException {

        extCAEntityManager.importCertificate("External_CA_1", x509CertificateSubKeyIdAsNull, true);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void importCertificate_AuthorityKeyIdentifier_Null() throws CertificateNotYetValidException {

        extCAEntityManager.importCertificate("External_CA_1", x509CertificateAuthKeyIdAsNull, true);
    }

    @Test
    public void importCertificate_CorrectCertificate() throws CertificateNotYetValidException {

        extCAEntityManager.importCertificate("External_CA_2",valid_x509Certificate, true);
    }

    @Test
    public void forceImportCertificate_CorrectCertificate() throws CertificateNotYetValidException {

        extCAEntityManager.forceImportCertificate("External_CA_2",valid_x509Certificate, true);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CertificateAlreadyExistsException.class)
    public void importCertificateAlreadyPresent() throws ExternalCAAlreadyExistsException, CertificateFieldException, ExternalCredentialMgmtServiceException {
        try {
            final List<CertificateData> certificateList = new ArrayList<CertificateData>();

            final CertificateData certificateData = new CertificateData();
            certificateData.setCertificate(x509Certificate.getEncoded());
            certificateData.setId(1);
            certificateData.setSerialNumber("xxx");
            certificateData.setIssuedTime(new Date());
            certificateData.setNotAfter(new Date());
            certificateData.setNotBefore(new Date());
            certificateData.setStatus(CertificateStatus.ACTIVE.getId());
            certificateList.add(certificateData);
            Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.anyString(), Mockito.anyMap())).thenReturn(certificateList);

            extCAEntityManager.importCertificate("External_CA_1", x509Certificate, false);
        } catch (final CertificateException e) {
            Assert.fail("error in test configuration!!!!!!!");
        }
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CertificateServiceException.class)
    public void listCertificatesWithException1() {
        try {
            Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenThrow(PersistenceException.class);
            extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);
        } catch (CertificateException | PersistenceException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    @Test(expected = InvalidEntityAttributeException.class)
    public void listCertificatesWithException2() {
        try {
            Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenThrow(CertificateException.class);
            extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);
        } catch (CertificateException | PersistenceException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @SuppressWarnings("unchecked")
    @Test(expected = InvalidEntityAttributeException.class)
    public void listCertificatesWithException3() {
        try {
            Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenThrow(IOException.class);
            extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);
        } catch (CertificateException | PersistenceException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    public void listCertificates() {
        final List<Certificate> certificateList = new ArrayList<>();
        final Certificate certificate = new Certificate();
        certificate.setId(1);
        certificate.setIssuedTime(new Date());
        certificate.setIssuer(new CertificateAuthority());
        certificate.setNotAfter(new Date());
        certificate.setNotBefore(new Date());
        certificate.setSerialNumber("xxx");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setX509Certificate(x509Certificate);
        certificateList.add(certificate);

        try {
            Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenReturn(certificateList);
            final List<Certificate> certificateListReturn = extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);
            assertEquals(certificateListReturn.get(0).getStatus(), CertificateStatus.ACTIVE);

        } catch (CertificateException | PersistenceException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test(expected = CertificateNotFoundException.class)
    public void listCertificates_CertificateNotFoundException() throws CertificateException, PersistenceException, IOException {

        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenReturn(null);

        extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);

    }

    @Test(expected = EntityNotFoundException.class)
    public void listCertificates_EntityNotFoundException() {

        Mockito.when(caPersistenceHelper.getCAEntity(Mockito.anyString())).thenReturn(createCAEntityData("ENM_CA", false));

        extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);

    }

    @Test(expected = EntityNotFoundException.class)
    public void listCertificates_EntityNotFoundException_CANotFoundExcepton() {

        Mockito.when(caPersistenceHelper.getCAEntity(Mockito.anyString())).thenThrow(new CANotFoundException());

        extCAEntityManager.listCertificates("External_CA_1", CertificateStatus.ACTIVE);

    }

    @Test
    public void exportCertificate() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException, ExternalCANotFoundException, CertificateNotFoundException,
            ExternalCredentialMgmtServiceException {

        final List<Certificate> certificateList = new ArrayList<>();
        final Certificate certificate = new Certificate();
        certificate.setId(1);
        certificate.setIssuedTime(new Date());
        certificate.setIssuer(new CertificateAuthority());
        certificate.setNotAfter(new Date());
        certificate.setNotBefore(new Date());
        certificate.setSerialNumber("xxx");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setX509Certificate(x509Certificate);
        certificateList.add(certificate);

        Mockito.when(caPersistenceHelper.getExternalCACertificate(Mockito.anyString(), Mockito.anyString())).thenReturn(certificate);
        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenReturn(certificateList);
        final X509Certificate certificateReturn = extCAEntityManager.getExternalCACertificate("External_CA_1", "01234");

        assertEquals(certificateReturn.getIssuerDN().toString(), "CN=MyRoot");
        assertEquals(certificateReturn.getSubjectDN().toString(), "CN=MyRoot");

    }

    @Test
    public void exportCertificate_WithSerialNoNull() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException, ExternalCANotFoundException,
            CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        final List<Certificate> certificateList = new ArrayList<>();
        final Certificate certificate = new Certificate();
        certificate.setId(1);
        certificate.setIssuedTime(new Date());
        certificate.setIssuer(new CertificateAuthority());
        certificate.setNotAfter(new Date());
        certificate.setNotBefore(new Date());
        certificate.setSerialNumber("xxx");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setX509Certificate(x509Certificate);
        certificateList.add(certificate);

        Mockito.when(caPersistenceHelper.getExternalCACertificate(Mockito.anyString(), Mockito.anyString())).thenReturn(certificate);
        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenReturn(certificateList);
        final X509Certificate certificateReturn = extCAEntityManager.getExternalCACertificate("External_CA_1", null);

        assertEquals(certificateReturn.getIssuerDN().toString(), "CN=MyRoot");
        assertEquals(certificateReturn.getSubjectDN().toString(), "CN=MyRoot");

    }

    @Test(expected = ExternalCANotFoundException.class)
    public void testGetExternalCACertificate_ExternalCANotFoundException() {

        Mockito.when(caPersistenceHelper.getCAEntity(Mockito.anyString())).thenReturn(createCAEntityData("ENM_CA", false));

        extCAEntityManager.getExternalCACertificate("External_CA_1", null);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetExternalCACertificate_CertificateNotFoundException() {

        Mockito.when(caPersistenceHelper.getCAEntity(Mockito.anyString())).thenReturn(createCAEntityData("ENM_CA", true));

        extCAEntityManager.getExternalCACertificate("External_CA_1", "012345");
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetExternalCACertificate() throws CertificateException, PersistenceException, IOException {

        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenReturn(null);

        extCAEntityManager.getExternalCACertificate("External_CA_1", null);
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void exportCertificate_ExternalCANotFoundException_CANotFoundException() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException,
            ExternalCANotFoundException, CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenThrow(new CANotFoundException());
        extCAEntityManager.getExternalCACertificate("External_CA_1", null);

    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void exportCertificate_ExternalCredentialMgmtServiceException() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException, ExternalCANotFoundException,
            CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenThrow(new CertificateException());
        extCAEntityManager.getExternalCACertificate("External_CA_1", null);

    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void exportCertificate_ExternalCredentialMgmtServiceException_PersistenceException() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException,
            ExternalCANotFoundException, CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        Mockito.when(caPersistenceHelper.getCertificatesForExtCA("External_CA_1", CertificateStatus.ACTIVE)).thenThrow(new PersistenceException());
        extCAEntityManager.getExternalCACertificate("External_CA_1", null);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void exportCertificate_MissingExtCAName() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException, ExternalCANotFoundException,
            CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        extCAEntityManager.getExternalCACertificate("", null);

    }

    @Test(expected = ExternalCANotFoundException.class)
    public void exportCertificate_ExtCANotFound() throws CertificateException, PersistenceException, IOException, MissingMandatoryFieldException, ExternalCANotFoundException,
            CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA_1")).thenThrow(new CANotFoundException());
        extCAEntityManager.getExternalCACertificate("External_CA_1", null);

    }

    /**
     * Method to test occurrence of ExternalCANotFoundException.
     */
    @Test(expected = ExternalCANotFoundException.class)
    public void testRemoveCertificate_ExternalCANotFoundException() {
        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(createCAEntityData("ENM_RootCA", false));

        extCAEntityManager.removeCertificate("External_CA");
    }

    /**
     * Method to test occurrence of ExternalCACRLsExistException.
     */
    @Test(expected = ExternalCACRLsExistException.class)
    public void testRemoveCertificate_ExternalCACRLsExistException() {

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(createCAEntityData("ENM_RootCA", true));

        extCAEntityManager.removeCertificate("External_CA");
    }

    /**
     * Method to test occurrence of ExternalCAInUseException.
     */
    @Test(expected = ExternalCAInUseException.class)
    public void testRemoveCertificate_ExternalCAInUseException() {

        final List<String> trustProfiles = new ArrayList<String>();
        trustProfiles.add("Profile1");

        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(createCAEntityData("ENM_RootCA", true))).thenReturn(trustProfiles);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(createCAEntityData("ENM_RootCA", true));

        extCAEntityManager.removeCertificate("External_CA");
    }

    /**
     * Method to test occurrence of ExternalCACRLsExistException.
     */
    @Test(expected = ExternalCACRLsExistException.class)
    public void testRemoveCertificate_ExternalCACRLsExistException_WithIssuerData() {

        final List<String> trustProfiles = new ArrayList<String>();

        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(createCAEntityData("ENM_RootCA", true))).thenReturn(trustProfiles);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(createCAEntityData("ENM_RootCA", true));

        extCAEntityManager.removeCertificate("External_CA");
    }

    /**
     * Method to test occurrence of ExternalCACRLsExistException.
     */
    @Test(expected = ExternalCACRLsExistException.class)
    public void testRemoveCertificate_ExternalCACRLsExistException_WithExternalCRlInfo() {

        final List<String> trustProfiles = new ArrayList<String>();

        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(createCAEntityData("ENM_RootCA", false))).thenReturn(trustProfiles);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(createCAEntityData("ENM_RootCA", true));

        extCAEntityManager.removeCertificate("External_CA");
    }

    /**
     * Method to test removeCertificate.
     */
    @Test
    public void testRemoveCertificate() {

        final CAEntityData cAEntityData = createCAEntityData("ENM_RootCA", true);
        cAEntityData.setAssociated(null);

        final List<String> trustProfiles = new ArrayList<String>();

        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(createCAEntityData("ENM_RootCA", true))).thenReturn(trustProfiles);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(cAEntityData);

        extCAEntityManager.removeCertificate("External_CA");

        Mockito.verify(persistenceManager, times(2)).updateEntity(Mockito.anyObject());

    }

    /**
     * Method to test ExternalCACRLsExistException.
     */
    @Test(expected = ExternalCACRLsExistException.class)
    public void testRemoveCertificate_ExternalCACRLsExistException_CRLInfo() {

        final CAEntityData cAEntityData = createCAEntityData("ENM_RootCA", false);
        cAEntityData.setExternalCA(true);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(cAEntityData);

        extCAEntityManager.removeCertificate("External_CA");

    }

    /**
     * Method to test occurrence of ExternalCredentialMgmtServiceException.
     */
    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void testRemoveCertificate_ExternalCredentialMgmtServiceException() {

        final CAEntityData cAEntityData = createCAEntityData("ENM_RootCA", true);
        cAEntityData.setAssociated(null);

        final List<String> trustProfiles = new ArrayList<String>();

        Mockito.when(caPersistenceHelper.getTrustProfileNamesUsingExtCA(createCAEntityData("ENM_RootCA", true))).thenReturn(trustProfiles);

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(cAEntityData);

        Mockito.when(persistenceManager.updateEntity(Mockito.anyObject())).thenThrow(new PersistenceException());

        extCAEntityManager.removeCertificate("External_CA");

    }

    /**
     * Method to test occurrence of ExternalCANotFoundException.
     */
    @Test(expected = ExternalCANotFoundException.class)
    public void testRemoveCertificate_ExternalCANotFoundException_WithCanotFound() {

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenThrow(new CANotFoundException());

        extCAEntityManager.removeCertificate("External_CA");

    }

    /**
     * Method to test occurrence of ExternalCAInUseException.
     */
    @Test(expected = ExternalCAInUseException.class)
    public void testRemoveCertificate_ExternalCAInUseException_WithIssuedcertificates() {

        List<CertificateData> certificateDatas = new ArrayList<CertificateData>();

        final CAEntityData cAEntityData = createCAEntityData("ENM_RootCA", true);
        cAEntityData.setAssociated(null);

        createSubCAEntityData("ENM_ExtSubCA", cAEntityData);

        certificateDatas.add(getCertificateData(cAEntityData));

        Mockito.when(caPersistenceHelper.getCAEntity("External_CA")).thenReturn(cAEntityData);

        Mockito.when(caPersistenceHelper.getCertificateDatas(cAEntityData.getId())).thenReturn(certificateDatas);

        extCAEntityManager.removeCertificate("External_CA");
    }

    /**
     * create CAEntity Data.
     *
     * @param caEntityName
     *            return CAEntityData
     */
    public static CAEntityData createCAEntityData(final String caEntityName, final boolean isRootCA) {
        final CAEntityData caEntityData = new CAEntityData();
        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final CAEntityData CAEntityData = setUPData.createCAEntityData(caEntityName, true);
        associated.add(CAEntityData);
        caEntityData.setAssociated(associated);
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName(caEntityName);
        certificateAuthorityData.setRootCA(isRootCA);
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(getCertificateData());
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        if (isRootCA) {
            caEntityData.setExternalCA(true);
            certificateAuthorityData.setSubjectDN("CN=MyRoot");
            caEntityData.getAssociated().remove(associated);

        } else {
            caEntityData.setExternalCA(false);
            certificateAuthorityData.setSubjectDN("CN=NotMyRoot");
            final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
            externalCrlInfoData.setId(1234);
            certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        }
        return caEntityData;
    }


    private CAEntityData createSubCAEntityData(final String caEntityName, CAEntityData rootCaEntityData) {
        final CAEntityData subCaEntityData = createCAEntityData(caEntityName, false);

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
                                certificateDatas.add(getCertificateData(rootCaEntityData));

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName(caEntityName);

        certificateAuthorityData.setExternalCrlInfoData(null);

        certificateAuthorityData.setCertificateDatas(certificateDatas);
        subCaEntityData.setCertificateAuthorityData(certificateAuthorityData);

        return subCaEntityData;
    }

    /**
     * Method to get CertificateData.
     * 
     * @return CertificateData.
     */
    private static CertificateData getCertificateData() {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1234);
        return certificateData;

    }

    private static CertificateData getCertificateData(CAEntityData issuerCAEntityData) {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(123);
        certificateData.setIssuerCA(issuerCAEntityData);
        return certificateData;

    }
}
