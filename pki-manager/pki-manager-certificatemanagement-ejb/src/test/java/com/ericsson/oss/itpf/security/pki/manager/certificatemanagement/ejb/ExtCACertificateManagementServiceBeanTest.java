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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb;

import static org.junit.Assert.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExtCACertificateManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.ejb.utility.CertificateManagementUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.ExtCAEntityManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACertificateManagementServiceBeanTest {

    @InjectMocks
    ExtCACertificateManagementServiceBean extCACertificateManagementServiceBean;

    @Mock
    private ExtCACertificateManagementAuthorizationManager externalCAManagementAuthorizationManager;

    @Mock
    ExtCAEntityManager extCAEntityCertificateManager;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CertificateManagementUtility certificateManagementUtility;

    private static SetUPData setupData;
    private final static String extCAName = "extCANAme";
    private static X509Certificate x509Certificate = null;
    private static ExternalCRLInfo crl = null;
    private static Certificate certificate = null;

    /**
     * Prepares initial set up required to run the test cases.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setup() {
        setupData = new SetUPData();
        try {
            certificate = setupData.getCertificate("certificates/ENMRootCA.crt");
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }
        x509Certificate = certificate.getX509Certificate();

    }

    @Test
    public void testImportCertificate() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException, ExternalCAAlreadyExistsException,
            ExternalCredentialMgmtServiceException {

        final List<CertificateData> certificateList = new ArrayList<CertificateData>();
        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(String.class), Mockito.anyMap())).thenReturn(certificateList);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, extCAName, "certificateAuthorityData.name")).thenReturn(null);

        Mockito.doNothing().when(persistenceManager).createEntity(Mockito.any(CAEntityData.class));
        Mockito.doNothing().when(persistenceManager).createEntity(Mockito.any(CertificateData.class));
        Mockito.when(persistenceManager.updateEntity(Mockito.any(CAEntityData.class))).thenReturn(null);

        extCACertificateManagementServiceBean.importCertificate(extCAName, x509Certificate, false);
        assertTrue(true);
    }

    @Test(expected = CertificateAlreadyExistsException.class)
    public void testImportCertificate_CertificateAlreadyExistsException() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException,
            ExternalCAAlreadyExistsException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new CertificateAlreadyExistsException("Exception occured while import certificate")).when(extCAEntityCertificateManager).importCertificate(extCAName, x509Certificate, false);
        extCACertificateManagementServiceBean.importCertificate(extCAName, x509Certificate, false);
    }

    @Test(expected = CertificateFieldException.class)
    public void testImportCertificate_CertificateFieldException() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException,
            ExternalCAAlreadyExistsException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new CertificateFieldException("Exception occured while import certificate")).when(extCAEntityCertificateManager).importCertificate(extCAName, x509Certificate, false);
        extCACertificateManagementServiceBean.importCertificate(extCAName, x509Certificate, false);
    }

    @Test(expected = ExternalCAAlreadyExistsException.class)
    public void testImportCertificate_ExtCAAlreadyExistsException() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException,
            ExternalCAAlreadyExistsException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new ExternalCAAlreadyExistsException("Exception occured while import certificate")).when(extCAEntityCertificateManager).importCertificate(extCAName, x509Certificate, false);

        extCACertificateManagementServiceBean.importCertificate(extCAName, x509Certificate, false);
    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void testImportCertificate_ExternalCredentialMgmtServiceException() throws MissingMandatoryFieldException, CertificateAlreadyExistsException, CertificateFieldException,
            ExternalCAAlreadyExistsException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new ExternalCredentialMgmtServiceException("Exception occured while import certificate")).when(extCAEntityCertificateManager).importCertificate(extCAName, x509Certificate, false);

        extCACertificateManagementServiceBean.importCertificate(extCAName, x509Certificate, false);
    }

    @Test
    public void testRemoveCA() throws MissingMandatoryFieldException, ExternalCANotFoundException, ExternalCAInUseException, ExternalCACRLsExistException, ExternalCredentialMgmtServiceException {
        final CAEntityData caEntity = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("EXT_CA1");
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        final ExternalCRLInfoData crlData = new ExternalCRLInfoData();
        final Set<CAEntityData> associatedList = new HashSet<CAEntityData>();
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        certificateAuthorityData.setExternalCrlInfoData(crlData);
        caEntity.setCertificateAuthorityData(certificateAuthorityData);
        caEntity.setExternalCA(true);
        caEntity.setAssociated(associatedList);
        final List<TrustProfileData> trustProfileDatas = new ArrayList<TrustProfileData>();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, extCAName, "certificateAuthorityData.name")).thenReturn(caEntity);
        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(String.class), Mockito.anyMap())).thenReturn(trustProfileDatas);
        Mockito.doNothing().when(persistenceManager).deleteEntity(Mockito.any(Object.class));
        Mockito.when(persistenceManager.updateEntity(Mockito.any(Object.class))).thenReturn(null);

        extCACertificateManagementServiceBean.remove(extCAName);
        assertTrue(true);
    }

    @Test
    public void testExportExtCACert() throws MissingMandatoryFieldException, ExternalCANotFoundException, CertificateNotFoundException, ExternalCredentialMgmtServiceException {

        Mockito.when(extCAEntityCertificateManager.getExternalCACertificate(extCAName, null)).thenReturn(x509Certificate);
        final List<X509Certificate> chain = extCACertificateManagementServiceBean.exportCertificate(extCAName, null, false);
        assertEquals(1, chain.size());
    }

    @Test
    public void testlistCertificatesAuthorized() {
        final String extCAName = "myExtCA";
        List<Certificate> certificateList = new ArrayList<>();
        certificateList.add(certificate);
        Mockito.when(extCAEntityCertificateManager.listCertificates(Mockito.any(), Mockito.any())).thenReturn(certificateList);
        extCACertificateManagementServiceBean.listCertificates(extCAName, CertificateStatus.ACTIVE);
    }

    @Test
    public void testlistExpiredCertificatesAuthorized() {
        final String extCAName = "myExtCA";
        List<Certificate> certificateList = new ArrayList<>();
        certificateList.add(certificate);
        Mockito.when(extCAEntityCertificateManager.listCertificates(Mockito.any(), Mockito.any())).thenReturn(certificateList);
        extCACertificateManagementServiceBean.listCertificates(extCAName, CertificateStatus.EXPIRED);
    }

    @Test
    public void testforceImportCertificate() {
        X509Certificate x509Certificate = null;
        Mockito.doNothing().when(extCAEntityCertificateManager).forceImportCertificate("test",x509Certificate, false);
        extCACertificateManagementServiceBean.forceImportCertificate("test", x509Certificate, true);
    }

    @Test(expected = SecurityViolationException.class)
    public void testlistCertificatesNotAuthorized() {
        final String extCAName = "myExtCA";
        Mockito.doThrow(SecurityViolationException.class).when(externalCAManagementAuthorizationManager).authorizeExtCACertificateMgmtOperations(ActionType.READ);
        extCACertificateManagementServiceBean.listCertificates(extCAName, CertificateStatus.ACTIVE);
    }

    @Test(expected = EntityNotFoundException.class)
    public void testlistCertificatesEntityNotFound() {
        final String extCAName = "myExtCA";
        Mockito.doThrow(MissingMandatoryFieldException.class).when(extCAEntityCertificateManager).listCertificates(extCAName, CertificateStatus.ACTIVE);
        extCACertificateManagementServiceBean.listCertificates(extCAName, CertificateStatus.ACTIVE);
    }

    /**
     * Method to test whether it returns an empty list if certificates are not found.
     *
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testListCertificates_EmptyList() throws CertificateException, IOException {
        final String entityName = "myExtCA";
        List<Certificate> returnedCertificates = null;

        Mockito.doNothing().when(externalCAManagementAuthorizationManager).authorizeExtCACertificateMgmtOperations(ActionType.READ);
        Mockito.when(extCAEntityCertificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenThrow(new CertificateNotFoundException("No Certificate found with ACTIVE status"));

        returnedCertificates = extCACertificateManagementServiceBean.listCertificates_v1(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
        assertNotNull(returnedCertificates);
        assertEquals(returnedCertificates.size(), 0);
    }
}
