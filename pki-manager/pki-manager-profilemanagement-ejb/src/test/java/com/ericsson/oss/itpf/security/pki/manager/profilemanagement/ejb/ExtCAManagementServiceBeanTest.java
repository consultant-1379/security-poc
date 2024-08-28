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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExternalCAManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;

@RunWith(MockitoJUnitRunner.class)
public class ExtCAManagementServiceBeanTest {

    @InjectMocks
    ExtCAManagementServiceBean extCAManagementServiceBean;

    @Mock
    ExternalCAManagementAuthorizationManager externalCAManagementAuthorizationManager;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    private ExtCAMapper extCaMapper;

    @Mock
    private Logger logger;

    @Mock
    EntitiesManager entitiesManager;

    @Test
    public void testGetExtCA() {
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("name");
        extCA.setCertificateAuthority(certificateAuthority);

        final CAEntityData caEntityActual = new CAEntityData();
        caEntityActual.setExternalCA(true);
        when(persistenceManager.findEntityByName(CAEntityData.class, extCA.getCertificateAuthority().getName(), "certificateAuthorityData.name")).thenReturn(caEntityActual);

        final ExtCA extCAActual = new ExtCA();

        final List<ExtCA> associated = new ArrayList<ExtCA>();
        final ExtCA associatedExtCA = new ExtCA();
        associated.add(associatedExtCA);
        extCAActual.setAssociated(associated);
        extCAActual.setCertificateAuthority(certificateAuthority);
        final ExternalCRLInfo externalCRLInfo = new ExternalCRLInfo();
        externalCRLInfo.setId(1);
        extCAActual.setExternalCRLInfo(externalCRLInfo);
        when(extCaMapper.toAPIFromModel(caEntityActual)).thenReturn(extCAActual);

        final ExtCA actualOutput = extCAManagementServiceBean.getExtCA(extCA);

        assertEquals(extCAActual.getAssociated().size(), actualOutput.getAssociated().size());
        assertEquals(extCAActual.getCertificateAuthority().getName(), actualOutput.getCertificateAuthority().getName());
        assertEquals(extCAActual.getExternalCRLInfo().getId(), actualOutput.getExternalCRLInfo().getId());
    }

    @Test
    public void testGetExtCAThrowsPersistenceException() {
        boolean isExternalCredentialMgmtServiceExceptionCaught = false;
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("name");
        extCA.setCertificateAuthority(certificateAuthority);

        final CAEntityData caEntityActual = new CAEntityData();
        caEntityActual.setExternalCA(true);
        doThrow(PersistenceException.class).when(persistenceManager).findEntityByName(CAEntityData.class, extCA.getCertificateAuthority().getName(), "certificateAuthorityData.name");

        try {
            extCAManagementServiceBean.getExtCA(extCA);
        } catch (final ExternalCredentialMgmtServiceException externalCredentialMgmtServiceException) {
            isExternalCredentialMgmtServiceExceptionCaught = true;
        }
        assertTrue(isExternalCredentialMgmtServiceExceptionCaught);
    }

    @Test
    public void testGetExtCAHavingCAEntityActualAsNull() {
        boolean isExternalCANotFoundExceptionCaught = false;
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("name");
        extCA.setCertificateAuthority(certificateAuthority);

        when(persistenceManager.findEntityByName(CAEntityData.class, extCA.getCertificateAuthority().getName(), "certificateAuthorityData.name")).thenReturn(null);

        try {
            extCAManagementServiceBean.getExtCA(extCA);
        } catch (final ExternalCANotFoundException ExceptionExternalCANotFoundException) {
            isExternalCANotFoundExceptionCaught = true;
        }
        assertTrue(isExternalCANotFoundExceptionCaught);
    }

    @Test
    public void testGetExtCAHavingCAEntityActualAsInternalCA() {
        boolean isExternalCANotFoundExceptionCaught = false;
        final ExtCA extCA = new ExtCA();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName("name");
        extCA.setCertificateAuthority(certificateAuthority);

        final CAEntityData caEntityActual = new CAEntityData();
        caEntityActual.setExternalCA(false);
        when(persistenceManager.findEntityByName(CAEntityData.class, extCA.getCertificateAuthority().getName(), "certificateAuthorityData.name")).thenReturn(caEntityActual);

        try {
            extCAManagementServiceBean.getExtCA(extCA);
        } catch (final ExternalCANotFoundException ExceptionExternalCANotFoundException) {
            isExternalCANotFoundExceptionCaught = true;
        }
        assertTrue(isExternalCANotFoundExceptionCaught);
    }

    @Test
    public void testGetExtCAs() {
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("externalCA", true);
        final List<CAEntityData> retievedExtCAs = new ArrayList<CAEntityData>();
        final CAEntityData retrievedExtCA = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        final CertificateData certificateData = new CertificateData();
        certificateDatas.add(certificateData);
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        retrievedExtCA.setCertificateAuthorityData(certificateAuthorityData);
        retievedExtCAs.add(retrievedExtCA);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, input)).thenReturn(retievedExtCAs);

        final ExtCA extCAActual = new ExtCA();
        when(extCaMapper.toAPIFromModel(retrievedExtCA)).thenReturn(extCAActual);

        final List<ExtCA> actualExtCAList = extCAManagementServiceBean.getExtCAs();
        assertEquals(extCAActual, actualExtCAList.get(0));
    }

    @Test
    public void testGetExtCAsThrowsPersistenceException() {
        boolean isExternalCredentialMgmtServiceException = false;
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("externalCA", true);
        final CAEntityData retrievedExtCA = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        final CertificateData certificateData = new CertificateData();
        certificateDatas.add(certificateData);
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        retrievedExtCA.setCertificateAuthorityData(certificateAuthorityData);
        doThrow(PersistenceException.class).when(persistenceManager).findEntitiesWhere(CAEntityData.class, input);

        final ExtCA extCAActual = new ExtCA();
        when(extCaMapper.toAPIFromModel(retrievedExtCA)).thenReturn(extCAActual);

        try {
            extCAManagementServiceBean.getExtCAs();
        } catch (final ExternalCredentialMgmtServiceException externalCredentialMgmtServiceException) {
            isExternalCredentialMgmtServiceException = true;
        }

        assertTrue(isExternalCredentialMgmtServiceException);
    }

    @Test
    public void testGetExtCAsBySubject() {
        final Subject subject = new Subject();
        assertNull(extCAManagementServiceBean.getExtCAsBySubject(subject));
    }

    @Test
    public void testIsExtCANameAvailable() {
        final String name = "Some Name";
        final CAEntityData caEntityActual = new CAEntityData();
        caEntityActual.setExternalCA(true);
        when(persistenceManager.findEntityByName(CAEntityData.class, name, "certificateAuthorityData.name")).thenReturn(caEntityActual);

        assertFalse(extCAManagementServiceBean.isExtCANameAvailable(name));
    }

    @Test
    public void testIsExtCANameAvailableNotHavingExternalCA() {
        final String name = "Some Name";
        final CAEntityData caEntityActual = new CAEntityData();
        caEntityActual.setExternalCA(false);
        when(persistenceManager.findEntityByName(CAEntityData.class, name, "certificateAuthorityData.name")).thenReturn(caEntityActual);

        assertTrue(extCAManagementServiceBean.isExtCANameAvailable(name));
    }

    @Test
    public void testIsExtCANameAvailableNotHavingCAEntityData() {
        final String name = "TestName";
        when(persistenceManager.findEntityByName(CAEntityData.class, name, "certificateAuthorityData.name")).thenReturn(null);

        assertTrue(extCAManagementServiceBean.isExtCANameAvailable(name));
    }

    @Test
    public void testIsExtCANameAvailableThrowsPersistenceException() {
        boolean isExternalCredentialMgmtServiceExceptionCaught = false;
        final String name = "TestName";
        final CAEntityData caEntityActual = new CAEntityData();
        caEntityActual.setExternalCA(true);
        doThrow(PersistenceException.class).when(persistenceManager).findEntityByName(CAEntityData.class, name, "certificateAuthorityData.name");

        try {
            extCAManagementServiceBean.isExtCANameAvailable(name);
        } catch (final ExternalCredentialMgmtServiceException ExternalCredentialMgmtServiceException) {
            isExternalCredentialMgmtServiceExceptionCaught = true;
        }
        assertTrue(isExternalCredentialMgmtServiceExceptionCaught);
    }

    @Test
    public void testGetTrustProfileByExtCA() {

        final CAEntityData caEntityData = new CAEntityData();
        when(persistenceManager.findEntityByName(CAEntityData.class, "TestCA", "certificateAuthorityData.name")).thenReturn(caEntityData);
        List<String> result = new ArrayList<String>();
        when(entitiesManager.getTrustProfileNamesByExtCA(caEntityData)).thenReturn(result);
        result = extCAManagementServiceBean.getTrustProfileByExtCA("TestCA");

        assertNotNull(result);
    }

    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void testGetTrustProfileByExtCAException() {

        final CAEntityData caEntityData = new CAEntityData();
        when(persistenceManager.findEntityByName(CAEntityData.class, "TestCA", "certificateAuthorityData.name")).thenThrow(PersistenceException.class);
        final List<String> result = new ArrayList<String>();
        when(entitiesManager.getTrustProfileNamesByExtCA(caEntityData)).thenReturn(result);

        extCAManagementServiceBean.getTrustProfileByExtCA("TestCA");
    }
}
