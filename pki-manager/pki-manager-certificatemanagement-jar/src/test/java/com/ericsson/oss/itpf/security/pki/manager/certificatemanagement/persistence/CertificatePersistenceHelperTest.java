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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.persistence;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class CertificatePersistenceHelperTest {

    @InjectMocks
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    private static CertificateData certificateData;
    private static CertificateIdentifier certificateIdentifier;
    private List<CertificateData> certDataList;
    private static Certificate certificate;
    private static CAEntityData caEntityData;
    private static List<Certificate> certificates;
    private static Map<String, Object> certificateMap;
    private static CertificateAuthority certificateAuthority;

    @Before
    public void setUp() {

        caEntityData = new CAEntityData();
        caEntityData.setId(10111);
        caEntityData.setExternalCA(true);

        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(10111);
        certificateAuthority.setName("subCA");

        certificate = new Certificate();
        certificate.setId(101);
        certificate.setIssuedTime(new Date());
        certificate.setSerialNumber("10101");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setIssuer(certificateAuthority);
        certificates = new LinkedList<Certificate>();

        certificates.add(certificate);

        certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName("Ericsson");
        certificateIdentifier.setSerialNumber("324567");

        certificateData = new CertificateData();
        certificateData.setId(101);
        certificateData.setSerialNumber("10101");
        certificateData.setIssuedTime(new Date());

        certDataList = new LinkedList<CertificateData>();
        certDataList.add(certificateData);

        certificateMap = new HashMap<String, Object>();
        certificateMap.put("serialNumber", certificateIdentifier.getSerialNumber());

    }

    @Test
    public void testGetCertificate() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        final Certificate certificate = certificatePersistenceHelper.getCertificate(certificateIdentifier);
        assertNotNull(certificate);
    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenThrow(new PersistenceException());

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCertificate_CertificateNotFoundException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(null);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

        Mockito.verify(persistenceManager, times(1)).findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH);
        try {
            Mockito.verify(certificateModelMapper, times(1)).toObjectModel(certDataList);
        } catch (CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(CertificateData.class, certificateMap);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException_2() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenThrow(new IOException());
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException_3() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenThrow(new CertificateException());
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException_4() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenThrow(new PersistenceException());

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = IssuerNotFoundException.class)
    public void testGetCertificate_IssuerNotFoundException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(null);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test
    public void testGetCertificateData() {

        certificateMap.clear();
        certificateMap.put("id", certificate.getId());

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificateData(certificate);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateData_CertificateServiceException() {

        final Map<String, Object> certificateMap = new HashMap<String, Object>();
        certificateMap.put("id", certificate.getId());

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenThrow(new PersistenceException());

        certificatePersistenceHelper.getCertificateData(certificate);

    }

    /**
     * Method to test occurrence of CertificateNotFoundException.
     */
    @Test(expected = CertificateNotFoundException.class)
    public void testGetCertificateBySerialNumber_CertificateNotFoundException() {
        certificatePersistenceHelper.getCertificateBySerialNumber("324567");

    }

    /**
     * Method to test getCertificateBySerialNumber.
     * 
     * @throws IOException
     * @throws CertificateException
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testGetCertificateBySerialNumber() throws CertificateException, IOException {

        certificateMap.remove("issuerCA");

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        Mockito.when(certificateModelMapper.toObjectModel(Mockito.anyList())).thenReturn(certificates);

        final List<Certificate> ExpectedCertificateList = certificatePersistenceHelper.getCertificateBySerialNumber("324567");

        assertNotNull(ExpectedCertificateList);

        assertEquals(1, ExpectedCertificateList.size());

        assertEquals(101, ExpectedCertificateList.get(0).getId());

        assertEquals("10101", ExpectedCertificateList.get(0).getSerialNumber());

        assertEquals(CertificateStatus.ACTIVE, ExpectedCertificateList.get(0).getStatus());

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     */
    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateBySerialNumber_CertificateServiceException() {

        certificateMap.remove("issuerCA");

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenThrow(new PersistenceException());

        certificatePersistenceHelper.getCertificateBySerialNumber("324567");

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     * 
     * @throws IOException
     * @throws CertificateException
     */
    @SuppressWarnings("unchecked")
    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateBySerialNumber_CertificateServiceException_WithCertificateException() throws CertificateException, IOException {

        certificateMap.remove("issuerCA");

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        Mockito.when(certificateModelMapper.toObjectModel(Mockito.anyList())).thenThrow(new CertificateException());

        certificatePersistenceHelper.getCertificateBySerialNumber("324567");

    }

    /**
     * Method to test occurrence of CertificateServiceException.
     * 
     * @throws IOException
     * @throws CertificateException
     */
    @SuppressWarnings("unchecked")
    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateBySerialNumber_CertificateServiceException_WithIOException() throws CertificateException, IOException {

        certificateMap.remove("issuerCA");

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        Mockito.when(certificateModelMapper.toObjectModel(Mockito.anyList())).thenThrow(new IOException());

        certificatePersistenceHelper.getCertificateBySerialNumber("324567");

    }

    /**
     * Method to test updateCertificateStatusToExpired.
     */
    @Test
    public void testUpdateCertificateStatusToExpired() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        certificatePersistenceHelper.updateCertificateStatusToExpired();

        Mockito.verify(persistenceManager).getEntityManager();
    }

    /**
     * Method to test updateCertificateStatusToRevoke
     */
    @Test
    public void testUpdateCertificateStatusToRevoke() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.executeUpdate()).thenReturn(1);
        certificatePersistenceHelper.updateCertificateStatusToRevoke("73447895");
    }

    /**
     * Method to test getCertificatesIssuedByExternalCA
     */
    @Test
    public void testGetCertificatesIssuedByExternalCA() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certDataList);
        final List<CertificateData> certificate = certificatePersistenceHelper.getCertificatesIssuedByExternalCA();
        assertEquals(certificate, certDataList);
    }
}
