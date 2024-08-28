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
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.EntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementLocalServiceBeanTest {

    @InjectMocks
    CertificateManagementLocalServiceBean certificateManagementLocalServiceBean;

    @Mock
    EntityCertificateManager entityCertificateManager;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    X509Certificate x509Certificate;

    private final String entityName = "New_Entity";

    @Test
    public void testGetCertificateChain() {

        List<CertificateChain> list = new ArrayList<CertificateChain>();
        list.add(new CertificateChain());

        Mockito.when(entityCertificateManager.getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE)).thenReturn(list);
        certificateManagementLocalServiceBean.getCertificateChain(entityName);
        Mockito.verify(entityCertificateManager).getCertificateChain(entityName, EntityType.ENTITY, Constants.INACTIVE_CERTIFICATE_VALID, CertificateStatus.ACTIVE);
    }

    @Test
    public void testGetTrustCertificates() {

        List<Certificate> list = new ArrayList<Certificate>();
        list.add(new Certificate());

        List<Certificate> trustedCertificates = new ArrayList<Certificate>();
        Certificate trustedCertificate = new Certificate();
        trustedCertificate.setId(0);
        trustedCertificates.add(trustedCertificate);

        Mockito.when(entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE)).thenReturn(list);

        Mockito.when(entityCertificateManager.removeDuplicatesCertificates(new ArrayList<Certificate>(trustedCertificates))).thenReturn(list);

        certificateManagementLocalServiceBean.getTrustCertificates(entityName);

        Mockito.verify(entityCertificateManager).getTrustCertificates(entityName, CertificateStatus.ACTIVE);

        Mockito.verify(entityCertificateManager).removeDuplicatesCertificates(new ArrayList<Certificate>(trustedCertificates));
    }

    @Test
    public void testGenerateCertificate() throws IOException {
        Certificate trustedCertificate = new Certificate();
        trustedCertificate.setId(0);

        CertificateRequest certificateRequest = new CertificateRequest();
        certificateRequest.setId(0);
        certificateRequest.setStatus(CertificateRequestStatus.NEW);

        Mockito.when(entityCertificateManager.generateCertificate(entityName, certificateRequest, RequestType.NEW)).thenReturn(trustedCertificate);
        certificateManagementLocalServiceBean.generateCertificate(entityName, certificateRequest);
        Mockito.verify(entityCertificateManager).generateCertificate(entityName, certificateRequest, RequestType.NEW);
    }

    @Test
    public void testGetEntityCertificates() throws IOException, CertificateException, PersistenceException {
        List<Certificate> list = new ArrayList<Certificate>();
        list.add(new Certificate());

        List<Certificate> entityCertificates = new ArrayList<Certificate>();
        Certificate entityCertificate = new Certificate();
        entityCertificate.setId(0);
        entityCertificates.add(entityCertificate);

        Mockito.when(entityCertificateManager.listCertificates(entityName, CertificateStatus.ACTIVE)).thenReturn(list);
        certificateManagementLocalServiceBean.getEntityCertificates(entityName);
        Mockito.verify(entityCertificateManager).listCertificates(entityName, CertificateStatus.ACTIVE);
    }

    @Test
    public void testValidateCertificateChain() throws IOException, CertificateException, PersistenceException {
        Certificate entityCertificate = new Certificate();
        entityCertificate.setId(0);

        Mockito.when(certificatePersistenceHelper.getCertificate(x509Certificate)).thenReturn(entityCertificate);
        certificateManagementLocalServiceBean.validateCertificateChain(x509Certificate);
        Mockito.verify(certificatePersistenceHelper).getCertificate(x509Certificate);
    }

}
