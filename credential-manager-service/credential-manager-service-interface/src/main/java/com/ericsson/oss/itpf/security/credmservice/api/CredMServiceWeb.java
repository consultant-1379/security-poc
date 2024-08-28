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
package com.ericsson.oss.itpf.security.credmservice.api;

import java.util.Set;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
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
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringAction;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerMonitoringResponse;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileType;

/**
 * (PRELIMINARY) This is an interface for credential management service and provides API's for below operations.
 * <ul>
 * <li>Reissue Certificate by Service Name.</li>
 * <li>Reissue Certificate by CA Name and Serial Number.</li>
 * </ul>
 */

@EService
@Remote
public interface CredMServiceWeb {

    /**
     * @param service
     *            The entityName of the service
     */
    void reissueCertificateByService(String service)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException;

    /**
     * @param caName
     *            The name of CA who signed the certificate
     * @param serialNumber
     *            The serialNumber of the certificate to reissue
     */
    void reissueCertificateBySN(String caName, String serialNumber) throws CredentialManagerCANotFoundException, CredentialManagerSNNotFoundException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException;

    /**
     *
     * @return The list of service running in the system.
     * @throws CredentialManagerInternalServiceException
     */
    Set<CredentialManagerEntity> getServices() throws CredentialManagerInternalServiceException;

    /**
     * @return The list of service running in the system with the own certificates information.
     * @throws CredentialManagerInternalServiceException
     */
    Set<CredentialManagerEntityCertificates> getServicesWithCertificates() throws CredentialManagerInternalServiceException;

    /**
     * @param caName
     *            the name of CA to trust
     * @return The list of service running in the system trusting the a CA
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInternalServiceException
     */
    Set<CredentialManagerEntity> getServicesByTrustCA(final String caName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException;

    /**
     * @param caName
     *            the name of CA to trust
     * @return The list of service running in the system trusting the a CA with the own certificates information.
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInternalServiceException
     */
    Set<CredentialManagerEntityCertificates> getServicesWithCertificatesByTrustCA(final String caName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException;

    void setLockProfile(final String profileName, final CredentialManagerProfileType profileType, final Boolean lock)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException;

    /**
     * Retrieve the monitoring status from the Credential Manager Controller
     *
     * @return The monitoring status for credmController.
     */
    CredentialManagerMonitoringResponse getMonitoringStatus();

    /**
     * Apply monitoring action to Credential Manager Controller and retrieve the previous monitoring status value
     *
     * @param CredentialManagerMonitoringAction
     *            action
     * @return monitoring status and http status for credmController.
     */
    CredentialManagerMonitoringResponse setMonitoringStatus(CredentialManagerMonitoringAction action);
}
