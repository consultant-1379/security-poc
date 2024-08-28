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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;

import javax.persistence.PersistenceException;
import javax.security.auth.x500.X500Principal;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.powermock.api.mockito.PowerMockito;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.api.CertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ImportCertificatePersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAHierarchyPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.CertificateUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;

@RunWith(MockitoJUnitRunner.class)
public class ImportCertificateHandlerTest {
    @InjectMocks
    ImportCertificateHandler importCertificateHandler;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Logger logger;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    Certificate certificate;

    @Mock
    CertificateManagementService coreCertificateManagementService;

    @Mock
    CAHierarchyPersistenceHandler caHierarchyPersistenceHandler;

    @Mock
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    @Test
    public void testImportCertificate() throws CertificateParsingException {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
        Mockito.verify(logger).info("Reissuing certificate for the CA hierarchy after import {} ", caName);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

    }

    @Test
    public void testImportCertificate_CAException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCAException()).when(importCertificatePersistenceHandler)
                .storeCertificate(caName, x509Certificate);
        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_InvalidCAException is failed");
        } catch (Exception exception) {
            assertEquals(InvalidCAException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.INACTIVE_CA));
            Mockito.verify(logger).error(Mockito.contains(ErrorMessages.INACTIVE_CA), Mockito.anyString());
        }
    }

    @Test
    public void testImportCertificate_isRootCA() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidOperationException()).when(importCertificatePersistenceHandler)
                .storeCertificate(caName, x509Certificate);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_InvalidOperationException is failed");
        } catch (Exception exception) {
            assertEquals(InvalidOperationException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.NOT_ROOT_CA));
            Mockito.verify(logger).error(Mockito.contains(ErrorMessages.NOT_ROOT_CA), Mockito.anyString());
        }
    }

    @Test
    public void testImportCertificateInvalidCertificateException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException()).when(importCertificatePersistenceHandler)
                .storeCertificate(caName, x509Certificate);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificateInvalidCertificateException failed");
        } catch (Exception exception) {
            assertEquals(InvalidCAException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.INVALID_CERTIFICATE));
            Mockito.verify(logger).error(Mockito.contains(ErrorMessages.INVALID_CERTIFICATE), Mockito.anyString());
        }
    }

    @Test
    public void testImportCertificate_CertificateAuthorityDoesNotExistException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException.class).when(importCertificatePersistenceHandler)
                .storeCertificate(caName, x509Certificate);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_CertificateAuthorityDoesNotExistException failed");
        } catch (Exception exception) {
            assertEquals(CANotFoundException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.ENTITY_NOT_FOUND));
            Mockito.verify(logger).error(Mockito.contains(ErrorMessages.ENTITY_NOT_FOUND), Mockito.anyString());
        }
    }

    @Test
    public void testImportCertificate_KeyPairGenerationException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException.class).when(importCertificatePersistenceHandler)
                .storeCertificate(caName, x509Certificate);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_KeyPairGenerationException failed");
        } catch (Exception exception) {
            assertEquals(com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException.class, exception.getClass());
        }
    }

    @Test
    public void testImportCertificate_RevocationServiceException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(RevocationServiceException.class).when(importCertificatePersistenceHandler).storeCertificate(caName, x509Certificate);
        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_RevocationServiceException failed");
        } catch (Exception exception) {
            assertEquals(RevocationServiceException.class, exception.getClass());
        }
    }

    @Test
    public void testImportCertificate_CertificateServiceException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException.class).when(importCertificatePersistenceHandler)
                .storeCertificate(caName, x509Certificate);
        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_CertificateServiceException failed");
        } catch (Exception exception) {
            assertEquals(CertificateServiceException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.INTERNAL_ERROR));
            Mockito.verify(logger).error(Mockito.contains(ErrorMessages.INTERNAL_ERROR), Mockito.anyString());
        }
    }

    @Test
    public void testImportCertificate_CertificateParsingException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(CertificateParsingException.class).when(importCertificatePersistenceHandler).storeCertificate(caName, x509Certificate);
        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_CertificateParsingException failed");
        } catch (Exception exception) {
            assertEquals(CertificateGenerationException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.ERROR_WHILE_IMPORT_CERT));
        }
    }

    @Test
    public void testImportCertificate_CertificateEncodingException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(CertificateEncodingException.class).when(importCertificatePersistenceHandler).storeCertificate(caName, x509Certificate);
        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_CertificateEncodingException failed");
        } catch (Exception exception) {
            assertEquals(CertificateGenerationException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.ERROR_WHILE_IMPORT_CERT));
        }
    }

    @Test
    public void testImportCertificate_PersistenceException() throws Exception {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(false);
        certificateAuthority.setStatus(CAStatus.INACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.doThrow(PersistenceException.class).when(importCertificatePersistenceHandler).storeCertificate(caName, x509Certificate);
        try {
            importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS);
            fail("testImportCertificate_PersistenceException failed");
        } catch (Exception exception) {
            assertEquals(CertificateServiceException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.INTERNAL_ERROR));
            Mockito.verify(logger).error(Mockito.contains(ErrorMessages.INTERNAL_ERROR), Mockito.anyString());
        }
    }

    @Test
    public void testImportCertificate_WithRevocation() throws CertificateParsingException {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);
        importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.REKEY_SUB_CAS_WITH_REVOCATION);
        Mockito.verify(logger).info("Reissuing certificate for the CA hierarchy after import {} ", caName);
    }

    @Test
    public void testImportCertificate_Renew() throws CertificateParsingException {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);
        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.RENEW_SUB_CAS);
        Mockito.verify(logger).info("Reissuing certificate for the CA hierarchy after import {} ", caName);
    }

    @Test
    public void testImportCertificate_RenewWithRevocation() throws CertificateParsingException {
        String caName = "RootCA";
        BigInteger serialNo = new BigInteger("999");
        X500Principal x500Principal = new X500Principal("CN=X500PrincipalName");

        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(caName);
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE.getId());

        CAEntityData cAEntityData = new CAEntityData();
        cAEntityData.setCertificateAuthorityData(certificateAuthority);
        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(serialNo);

        PowerMockito.mockStatic(CertificateUtils.class);

        Mockito.when(x509Certificate.getSubjectX500Principal()).thenReturn(x500Principal);
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(caName)).thenReturn(cAEntityData);
        Mockito.when(certificatemanagementEserviceProxy.getCoreCertificateManagementService()).thenReturn(coreCertificateManagementService);

        importCertificateHandler.importCertificate(caName, x509Certificate, true, CAReIssueType.RENEW_SUB_CAS_WITH_REVOCATION);
        Mockito.verify(logger).info("Reissuing certificate for the CA hierarchy after import {} ", caName);
    }

}
