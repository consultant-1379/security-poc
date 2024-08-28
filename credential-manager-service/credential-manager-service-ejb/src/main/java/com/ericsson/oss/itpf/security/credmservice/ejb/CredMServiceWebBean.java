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
package com.ericsson.oss.itpf.security.credmservice.ejb;

import java.util.Set;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.api.CredMServiceWeb;
import com.ericsson.oss.itpf.security.credmservice.api.CredmControllerManager;
import com.ericsson.oss.itpf.security.credmservice.api.ProfileManager;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCANotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerSNNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringAction;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;

@Stateless
public class CredMServiceWebBean implements CredMServiceWeb {

    private static final Logger log = LoggerFactory.getLogger(CredMServiceWebBean.class);

    @Inject
    ProfileManager profileManager;

    @Inject
    CredmControllerManager credmControllerManager;

    @Override
    public void reissueCertificateByService(final String service)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        log.info("reissueCertificateByService:  service: " + service);
        profileManager.reissue(service);
    }

    @Override
    public void reissueCertificateBySN(final String caName, final String serialNumber)
            throws CredentialManagerCANotFoundException, CredentialManagerSNNotFoundException, CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException {
        log.info("reissueCertificateBySN:  caName: " + caName + " serialNumber: " + serialNumber);
        profileManager.reissue(caName, serialNumber);
    }

    @Override
    public Set<CredentialManagerEntity> getServices() throws CredentialManagerInternalServiceException {
        return profileManager.getServices();
    }

    @Override
    public Set<CredentialManagerEntityCertificates> getServicesWithCertificates() throws CredentialManagerInternalServiceException {
        return profileManager.getServicesWithCertificates();
    }

    @Override
    public Set<CredentialManagerEntity> getServicesByTrustCA(final String caName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {
        return profileManager.getServicesByTrustCA(caName);
    }

    @Override
    public Set<CredentialManagerEntityCertificates> getServicesWithCertificatesByTrustCA(final String caName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException {
        return profileManager.getServicesWithCertificatesByTrustCA(caName);
    }

    @Override
    public void setLockProfile(final String profileName, final CredentialManagerProfileType profileType, final Boolean lock)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException {
        profileManager.setLockProfile(profileName, profileType, lock);
    }

    @Override
    public CredentialManagerMonitoringResponse getMonitoringStatus() {
        return credmControllerManager.getMonitoring();
    }

    @Override
    public CredentialManagerMonitoringResponse setMonitoringStatus(final CredentialManagerMonitoringAction action) {
        return credmControllerManager.setMonitoring(action);
    }

}
