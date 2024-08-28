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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExtCACRLManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.ExtCACRLManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACRLManagementServiceBeanTest {

    @Mock
    ExtCACRLManager extCACLRManager;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @InjectMocks
    ExtCACRLManagementServiceBean extCACertificateManagementServiceBean;

    @Mock
    ExtCACRLManagementAuthorizationManager extCACRLManagementAuthorizationManager;

    private static SetUPData setupData;
    private final static String extCAName = "extCANAme";
    private static ExternalCRLInfo crl = null;

    /**
     * Prepares initial set up required to run the test cases.
     *
     * @throws Exception
     */
    @BeforeClass
    public static void setup() {
        setupData = new SetUPData();
        try {
            crl = setupData.getExternalCRLInfo("crls/testCA.crl");
        } catch (CertificateException | IOException e) {
            e.printStackTrace();
        }

    }

    @Test
    public void testAddCRL() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, extCAName, "certificateAuthorityData.name")).thenReturn(null);
        Mockito.doNothing().when(persistenceManager).deleteEntity(Mockito.any(ExternalCRLInfoData.class));
        Mockito.doNothing().when(persistenceManager).createEntity(Mockito.any(ExternalCRLInfoData.class));

        Mockito.when(persistenceManager.updateEntity(Mockito.any(CAEntityData.class))).thenReturn(null);
        extCACertificateManagementServiceBean.addExternalCRLInfo(extCAName, crl);
        assertTrue(true);
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void testAddCRL_ExternalCANotFoundException() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new ExternalCANotFoundException("Exception occured while Add CRL into certificate")).when(extCACLRManager).addCRL(extCAName, crl);

        extCACertificateManagementServiceBean.addExternalCRLInfo(extCAName, crl);
    }

    @Test(expected = ExternalCRLException.class)
    public void testAddCRL_ExternalCRLException() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new ExternalCRLException("Exception occured while Add CRL into certificate")).when(extCACLRManager).addCRL(extCAName, crl);

        extCACertificateManagementServiceBean.addExternalCRLInfo(extCAName, crl);
    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void testAddCRL_ExternalCredentialMgmtServiceException() throws ExternalCANotFoundException, ExternalCRLException, ExternalCredentialMgmtServiceException {

        Mockito.doThrow(new ExternalCredentialMgmtServiceException("Exception occured while Add CRL into certificate")).when(extCACLRManager).addCRL(extCAName, crl);

        extCACertificateManagementServiceBean.addExternalCRLInfo(extCAName, crl);
    }

    @Test
    public void testListExternalCRLInfo() {
        final List<ExternalCRLInfo> externalCRLInfoList = new ArrayList<ExternalCRLInfo>();
        when(extCACLRManager.listExternalCRLInfo(extCAName)).thenReturn(externalCRLInfoList);
        assertEquals(externalCRLInfoList, extCACertificateManagementServiceBean.listExternalCRLInfo(extCAName));
    }

    @Test
    public void testRemove() {
        extCACertificateManagementServiceBean.remove(extCAName);

        verify(extCACLRManager).removeAllCRLs(extCAName);
    }

    @Test
    public void testGetCRLByCACertificate() {
        final CACertificateIdentifier caCertIdentifier = new CACertificateIdentifier();
        assertNull(extCACertificateManagementServiceBean.getCRLByCACertificate(caCertIdentifier));
    }

    @Test
    public void testGetAllCRLs() {
        final CACertificateIdentifier caCertIdentifier = new CACertificateIdentifier();
        assertNull(extCACertificateManagementServiceBean.getAllCRLs(caCertIdentifier));
    }

    @Test
    public void testGetCRLbyCAName() {
        final String caEntityName = "";
        final boolean isChainRequired = false;
        final CertificateStatus status = null;
        assertNull(extCACertificateManagementServiceBean.getCRL(caEntityName, status, isChainRequired));
    }

    @Test
    public void testGenerateCRL() throws CANotFoundException, CertificateNotFoundException, CRLGenerationException, CRLServiceException, ExpiredCertificateException, RevokedCertificateException {
        extCACertificateManagementServiceBean.generateCRL(null);
    }

    @Test
    public void tetGetCRLByCACertificate() throws CANotFoundException, CertificateNotFoundException, CRLNotFoundException, CRLServiceException, ExpiredCertificateException,
            RevokedCertificateException {
        extCACertificateManagementServiceBean.getCRLByCACertificate(null);
    }

    @Test
    public void testGetCRL() throws CANotFoundException, CertificateNotFoundException, InvalidCertificateStatusException, CRLServiceException {
        extCACertificateManagementServiceBean.getCRL(null, null);
    }

    @Test
    public void testPublishCRLToCDPS() throws CRLServiceException {
        extCACertificateManagementServiceBean.publishCRLToCDPS(null);
    }

    @Test
    public void testUnpublishCRLFromCDPS() throws CRLServiceException {
        extCACertificateManagementServiceBean.unpublishCRLFromCDPS(null);
    }

    @Test
    public void generateCRL() throws InvalidCertificateStatusException {
        extCACertificateManagementServiceBean.generateCRL(null, null);
    }

    @Test
    public void testRemoveExtCrl() {
        extCACertificateManagementServiceBean.removeExtCRL(extCAName, "issuerName");
        verify(extCACLRManager).removeCRLs(extCAName, "issuerName");
    }

    @Test
    public void testRemoveExtCrlInfo() {
        Integer crlAutoUpdateTimer = new Integer(9);
        extCACertificateManagementServiceBean.configExternalCRLInfo("", true, crlAutoUpdateTimer);
        verify(extCACLRManager).configCRLInfo("", true, crlAutoUpdateTimer);
    }

}