/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.ejb;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCANotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.impl.ProfileManagerImpl;
import com.ericsson.oss.services.security.pkimock.api.MockEntityManagementService;

@RunWith(MockitoJUnitRunner.class)
public class CredMServiceWebBeanTest {

    @Mock
    ProfileManagerImpl profileManager;

    @Mock
    MockEntityManagementService mockEntityManagerService;

    @InjectMocks
    CredMServiceWebBean credMServiceWebBean;

    @Test
    public void reissueByEntityName()
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        credMServiceWebBean.reissueCertificateByService("ServiceName");
    }

    @Test
    public void getServices() throws CredentialManagerInternalServiceException {
        final Set<CredentialManagerEntity> entitySet = new HashSet<CredentialManagerEntity>();
        for (int i = 0; i < 3; i++) {
            final CredentialManagerEntity entity = new CredentialManagerEntity();
            entity.setEntityProfileName("entityProfileName" + i);
            entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
            entity.setEntityType(CredentialManagerEntityType.ENTITY);
            entity.setId(i);
            entity.setKeyGenerationAlgorithm(null);
            entity.setName("Entity" + i);
            entitySet.add(entity);
        }

        when(profileManager.getServices()).thenReturn(entitySet);

        final Set<CredentialManagerEntity> entities = credMServiceWebBean.getServices();

        assertEquals(3, entities.size());

    }

    @Test
    public void getServicesWithCert() throws CredentialManagerInternalServiceException {
        final Set<CredentialManagerEntityCertificates> entitySet = new HashSet<CredentialManagerEntityCertificates>();
        for (int i = 0; i < 3; i++) {
            final CredentialManagerEntityCertificates entity = new CredentialManagerEntityCertificates();
            entity.setEntityProfileName("entityProfileName" + i);
            entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
            entity.setEntityType(CredentialManagerEntityType.ENTITY);
            entity.setId(i);
            entity.setKeyGenerationAlgorithm(null);
            entity.setName("Entity" + i);
            entitySet.add(entity);
            final List<CredentialManagerX509Certificate> certs = new ArrayList();
            entity.setCerts(certs);
        }

        when(profileManager.getServicesWithCertificates()).thenReturn(entitySet);

        final Set<CredentialManagerEntityCertificates> entities = credMServiceWebBean.getServicesWithCertificates();

        assertEquals(3, entities.size());

    }

    @Test
    public void getServicesWithCertByTrustCAName()
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {
        final Set<CredentialManagerEntityCertificates> entitySet = new HashSet<CredentialManagerEntityCertificates>();
        for (int i = 0; i < 3; i++) {
            final CredentialManagerEntityCertificates entity = new CredentialManagerEntityCertificates();
            entity.setEntityProfileName("entityProfileName" + i);
            entity.setEntityStatus(CredentialManagerEntityStatus.ACTIVE);
            entity.setEntityType(CredentialManagerEntityType.ENTITY);
            entity.setId(i);
            entity.setKeyGenerationAlgorithm(null);
            entity.setName("Entity" + i);
            entitySet.add(entity);
            final List<CredentialManagerX509Certificate> certs = new ArrayList();
            entity.setCerts(certs);
        }

        when(profileManager.getServicesWithCertificatesByTrustCA(any(String.class))).thenReturn(entitySet);

        final Set<CredentialManagerEntityCertificates> entities = credMServiceWebBean.getServicesWithCertificatesByTrustCA("CAName");

        assertEquals(3, entities.size());

    }

    @Test(expected = CredentialManagerInvalidArgumentException.class)
    public void getServicesByTrustCANameFails()
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {

        when(profileManager.getServicesByTrustCA(any(String.class))).thenThrow(new CredentialManagerInvalidArgumentException());

        final Set<CredentialManagerEntity> entities = credMServiceWebBean.getServicesByTrustCA("CAName");

    }

}
