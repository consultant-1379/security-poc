/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.*;
import java.util.*;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACertificatePersistanceHandlerTest {

    @InjectMocks
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    static PersistenceManager persistenceManager;

    @Mock
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityPersistenceHandler<CAEntity> caEntityPersistenceHandler;

    @Mock
    ExternalCRLMapper crlMapper;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    Logger logger;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    ExtCertificateModelMapper extCertificateModelMapper;

    @Mock
    SystemRecorder systemRecorder;

    private Certificate certificate;
    private CertificateData certificateData;
    private List<CertificateData> certDataList;
    private X509Certificate x509Certificate;
    private static X509Certificate x509CertificateAuthKeyIdAsNull;
    private CAEntity caEntity;
    private CAEntityData caEntityData;
    private CertificateAuthorityData certificateAuthorityData;

    private static SetUPData setupData;

    @Before
    public void setUp() throws CertificateException, IOException {

        setupData = new SetUPData();

        certificate = new Certificate();

        certificateData = new CertificateData();
        certificateData.setId(101);
        certificateData.setSerialNumber("10101");
        certificateData.setIssuedTime(new Date());

        certDataList = new LinkedList<CertificateData>();
        certDataList.add(certificateData);

        x509Certificate = setupData.getX509Certificate("certificates/Entity.crt");
        x509CertificateAuthKeyIdAsNull = setupData.getX509Certificate("certificates/AuthorityKeyIdentifierAsNullInCert.crt");
        certificate.setX509Certificate(x509Certificate);

        caEntityData = new CAEntityData();

        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setRootCA(true);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
    }

    @Test
    public void testPopulateExternalCACertificates() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));
        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(certDataList);

        extCACertificatePersistanceHandler.populateExternalCACertificates();
    }

    @Test
    public void testGetIssuerCertificateData() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        assertNotNull(extCACertificatePersistanceHandler.getIssuerCertificateData(x509Certificate));

    }

    @Test
    public void testGetCertificateData() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/Entity.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        extCACertificatePersistanceHandler.getCertificateData(x509Certificate);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCertificateDataForException() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        extCACertificatePersistanceHandler.getCertificateData(x509Certificate);
    }

    @Test
    public void testGetIssuerX509Certificate() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetIssuerX509CertificateForException() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/Entity.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate);
    }

    @Test
    public void testvalidateCertificateChain() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/Entity.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        extCACertificatePersistanceHandler.validateCertificateChain(x509Certificate);
    }

    @Test
    public void testUpdateIssuerCertificateChain() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/RootCA.crt", "‎48 06 83 17 ee b7 7a a9");
        CertificateData subCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        CertificateData entityCertificateData = setupData.createCertificateData("certificates/Entity.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);
        cerList.add(entityCertificateData);
        cerList.add(subCertificateData);
        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        extCACertificatePersistanceHandler.updateIssuerCertificateChain(x509Certificate);
    }

    @Test
    public void testGetExtCACertificatesData() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));
        final List<CertificateData> extCACertsData = extCACertificatePersistanceHandler.getCertificateDatasForExtCA("caEntityName", CertificateStatus.ACTIVE);
        assertNotNull(extCACertsData);
    }

    @Test
    public void testGetEmptyExtCACertificatesData() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        final List<CertificateData> actualExtCAcertaData = extCACertificatePersistanceHandler.getCertificateDatasForExtCA("caEntityName", CertificateStatus.ACTIVE);
        assertNull(actualExtCAcertaData);
    }

    @Test
    public void testGetExtCACertificates() throws CertificateException, PersistenceException, IOException {
        final List<Certificate> certList = new ArrayList<Certificate>();
        final Certificate cert = new Certificate();

        certList.add(cert);

        Mockito.when(extCertificateModelMapper.toObjectModel(certDataList)).thenReturn(certList);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        final List<Certificate> certificates = extCACertificatePersistanceHandler.getCertificatesForExtCA("caEntityName", CertificateStatus.ACTIVE);
        assertNotNull(certificates);
    }

    @Test
    public void testSetIssuerToExtCertNoChain() throws CertificateEncodingException {

        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setName("caAutName");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        extCACertificatePersistanceHandler.setIssuerToExtCertificate(caEntityData, certificateData, false);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testSetIssuerToExtCertCertificateNotFoundException() throws CertificateEncodingException {

        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateAuthorityData.setRootCA(false);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        extCACertificatePersistanceHandler.setIssuerToExtCertificate(caEntityData, certificateData, true);
    }

    @Test
    public void testSetIssuerToExtCertToNotRoot() throws CertificateException, IOException {

        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setName("caAutName");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        final CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        final List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getSingleResult()).thenReturn(caEntityData);
        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);

        extCACertificatePersistanceHandler.setIssuerToExtCertificate(caEntityData, certificateData, false);
    }

    @Test(expected = CANotFoundException.class)
    public void testSetIssuerToExtCertToNotRootCANotFoundException() throws CertificateException, IOException {
        certificateData.setCertificate(certificate.getX509Certificate().getEncoded());
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setName("caAutName");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        final CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        final List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);

        extCACertificatePersistanceHandler.setIssuerToExtCertificate(caEntityData, certificateData, false);
    }

    @Test
    public void testupdateIssuerAndSubjectForExtCertificate() throws CANotFoundException, CertificateNotFoundException, CertificateException, PersistenceException, IOException {

        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(certificate);
        caEntityData.setExternalCA(true);
        Mockito.when(extCACertificatePersistanceHandler.getCAEntity("caEntityName")).thenReturn(caEntityData);
        Mockito.when(extCertificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);
        extCACertificatePersistanceHandler.updateIssuerAndSubjectForExtCertificate("caEntityName", certificates);
    }

    @Test
    public void testGetIssuerCertificateDataWhenSubKeyIdNull() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubjectKeyIdentifierAsNullInCert.crt", "‎ca 39 17 32 36 89 53 2b");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        assertNull(extCACertificatePersistanceHandler.getIssuerCertificateData(x509Certificate));

    }

    @Test
    public void testGetIssuerCertificateDataWhenAuthKeyIdNull() throws CertificateEncodingException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        CertificateData rootCertificateData = setupData.createCertificateData("certificates/SubCA.crt", "‎48 06 83 17 ee b7 7a a9");
        List<CertificateData> cerList = new LinkedList<CertificateData>();
        cerList.add(rootCertificateData);

        Mockito.when(extCACertificatePersistanceHandler.getAllExternalCACertificates()).thenReturn(cerList);
        extCACertificatePersistanceHandler.populateExternalCACertificates();
        assertNull(extCACertificatePersistanceHandler.getIssuerCertificateData(x509CertificateAuthKeyIdAsNull));

    }
}
