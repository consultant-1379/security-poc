/*------------------------------------------------------------------------------
 *******************************************************************************
 *-- * COPYRIGHT Ericsson 2014
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

import javax.ejb.Local;

import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCANotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerSNNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCALists;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityCertificates;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;

@Local
public interface ProfileManager {

    CredentialManagerEntity getEntity(final String entityName) throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException;

    CredentialManagerEntity createEntity(final String entityName, final CredentialManagerSubject subject,
                                         final CredentialManagerSubjectAltName subjectAltName,
                                         final CredentialManagerAlgorithm keyGenerationAlgorithm, final String entityProfileName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException;

    CredentialManagerEntity updateEntity(final String entityName, final CredentialManagerSubject subject,
                                         final CredentialManagerSubjectAltName subjectAltName,
                                         final CredentialManagerAlgorithm keyGenerationAlgorithm, final String endEntityProfileName)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidArgumentException;

    CredentialManagerProfileInfo getProfile(final String entityProfileName) throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException;

    /**
     * @param endEntityProfileName
     * @return
     * @throws CredentialManagerInvalidProfileException
     * @throws CredentialManagerServiceException
     */
    CredentialManagerCALists getTrustCAList(String endEntityProfileName) throws CredentialManagerInvalidArgumentException,
            CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException;

    /**
     * getTrustCAListFromTP
     *
     * @param trustProfileName
     * @param caLists
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInternalServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerInvalidProfileException
     */
    public CredentialManagerCALists getTrustCAListFromTP(final String trustProfileName, CredentialManagerCALists caLists)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException;

    /**
     * @param entityName
     * @return
     * @throws CredentialManagerInternalServiceException
     * @throws CredentialManagerInvalidEntityException
     */
    boolean isEntityPresent(String entityName) throws CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException;

    /**
     * @param categoryName
     * @return
     */
    Set<CredentialManagerEntity> getEntitiesByCategory(String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException;

    /**
     * @param categoryName
     * @return
     */
    Set<CredentialManagerEntity> getEntitiesSummaryByCategory(String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException;


    /**
     * @param entityName
     * @param otp
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerEntityNotFoundException
     * @throws CredentialManagerInternalServiceException
     */
    boolean isOTPValid(String entityName, String otp)
            throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException;

    /**
     * @param service
     */
    void reissue(String service)
            throws CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException;

    /**
     * @param caname
     *            , serialNumber
     */
    void reissue(String caName, String serialNumber) throws CredentialManagerCANotFoundException, CredentialManagerSNNotFoundException,
            CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException, CredentialManagerInvalidEntityException;

    Set<CredentialManagerEntity> getServices() throws CredentialManagerInternalServiceException;

    Set<CredentialManagerEntityCertificates> getServicesWithCertificates() throws CredentialManagerInternalServiceException;

    Set<CredentialManagerEntity> getServicesByTrustCA(final String trustCAName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException;

    Set<CredentialManagerEntityCertificates> getServicesWithCertificatesByTrustCA(final String trustCAName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerCANotFoundException, CredentialManagerInternalServiceException;

    void setLockProfile(final String profileName, final CredentialManagerProfileType profileType, final Boolean lock)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerInvalidProfileException;

}
