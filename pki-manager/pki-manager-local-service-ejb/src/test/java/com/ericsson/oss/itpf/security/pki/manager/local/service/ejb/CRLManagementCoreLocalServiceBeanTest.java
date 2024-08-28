/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.local.service.ejb;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class CRLManagementCoreLocalServiceBeanTest {

    @InjectMocks
    CRLManagementCoreLocalServiceBean cRLManagementCoreLocalServiceBean;

    @Mock
    CRLManagementService coreCRLManagementService;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    CRLInfo crlInfo;

    @Mock
    CACertificateIdentifier caCertIdentifier;

    private CACertificateIdentifier caCertificateIdentifier;
    private static final String caName = "ENM_RootCA";
    private static final String cerficateSerialNumber = "1508f262d31";

    @Test
    public void testGenerateCrl_Success() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertIdentifier)).thenReturn(new CRLInfo());
        cRLManagementCoreLocalServiceBean.generateCrl(caCertIdentifier);
        Mockito.verify(coreCRLManagementService).generateCRL(caCertIdentifier);
    }

    @Before
    public void setUpData() {
        caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName(caName);
        caCertificateIdentifier.setCerficateSerialNumber(cerficateSerialNumber);

    }

    @Test
    public void testGenerateCrl() {
        cRLManagementCoreLocalServiceBean.generateCrl(caCertificateIdentifier);
        Mockito.verify(coreCRLManagementService).generateCRL(caCertificateIdentifier);
    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGenerateCrl_CertificateNotFoundException() {
        final String CertificateNotFound = "Certificate Not found";
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(
                new com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException(CertificateNotFound));
        cRLManagementCoreLocalServiceBean.generateCrl(caCertificateIdentifier);
        Mockito.verify(coreCRLManagementService).generateCRL(caCertificateIdentifier);
    }

    @Test(expected = CANotFoundException.class)
    public void testGenerateCrl_CANotFoundException() {
        Mockito.when(coreCRLManagementService.generateCRL(caCertificateIdentifier)).thenThrow(new com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException());
        cRLManagementCoreLocalServiceBean.generateCrl(caCertificateIdentifier);
        Mockito.verify(coreCRLManagementService).generateCRL(caCertificateIdentifier);
    }
}
