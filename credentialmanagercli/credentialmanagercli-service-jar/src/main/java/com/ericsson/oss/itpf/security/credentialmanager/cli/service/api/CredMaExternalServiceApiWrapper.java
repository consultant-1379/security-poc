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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;

public interface CredMaExternalServiceApiWrapper {

    /**
     * 
     * @return
     */
    String getCredentialManagerInterfaceVersion();

    /**
     * for test purpose only
     * 
     * @param category
     * @return
     * @throws GetEndEntitiesByCategoryException
     * @throws InvalidCategoryNameException
     */
    List<EntitySummary> getEndEntitiesByCategory(String category) throws GetEndEntitiesByCategoryException, InvalidCategoryNameException;

    /**
     * for test purpose only
     * 
     * @param entityInfo
     * @param ksInfo
     * @return
     * @throws IssueCertificateException
     * @throws InvalidCertificateFormatException
     * @throws EntityNotFoundException
     */
    Boolean issueCertificateForENIS(EntityInfo entityInfo, KeystoreInfo ksInfo) throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException,
            OtpExpiredException;

    /**
     * for test purpose only
     * 
     * @param entityInfo
     * @param ksInfo
     * @param revocationReason
     * @return A Boolean reporting the result of the operation.
     * @throws ReissueCertificateException
     * @throws InvalidCertificateFormatException
     * @throws EntityNotFoundException
     */
    Boolean reIssueCertificate(EntityInfo entityInfo, KeystoreInfo ksInfo, CrlReason revocationReason) throws ReissueCertificateException, EntityNotFoundException, InvalidCertificateFormatException,
            OtpNotValidException, OtpExpiredException;

    /**
     * for test purpose only
     * 
     * @param entityInfo
     * @param revocationReason
     * @return A Boolean reporting the result of the operation.
     * @throws RevokeCertificateException
     * @throws EntityNotFoundException
     */
    Boolean revokeCertificate(EntityInfo entityInfo, CrlReason revocationReason) throws RevokeCertificateException, EntityNotFoundException;

    /**
     * for test purpose only
     * 
     * @param entityName
     * @param entityType
     * @param certificateStatus
     * @return a List of CertificateSummary.
     * @throws CertificateNotFoundException
     * @throws GetCertificatesByEntityNameException
     * @throws EntityNotFoundException
     */
    List<CertificateSummary> getCertificatesByEntityName(String entityName, EntityType entityType, CertificateStatus... certificateStatus) throws CertificateNotFoundException,
            GetCertificatesByEntityNameException, EntityNotFoundException;

    /**
     * 
     * for test purpose only
     * 
     * @param issuerDN
     * @param subjectDN
     * @param certificateSN
     * @param revocationReason
     * 
     * @return Boolean
     * 
     * @throws CertificateNotFoundException
     * @throws ExpiredCertificateException
     * @throws AlreadyRevokedCertificateException
     * @throws RevokeEntityCertificateException
     */
    Boolean revokeEntityCertificate(String issuerDN, String subjectDN, String certificateSN, CrlReason revocationReason) throws CertificateNotFoundException, ExpiredCertificateException,
            AlreadyRevokedCertificateException, RevokeEntityCertificateException;

    /**
     * 
     * @param entityInfo
     * @param certificateLocation
     * @param certificateChain
     * @param passwordLocation
     * @param revocationReason
     * @return
     * @throws ReIssueLegacyXMLCertificateException
     * @throws EntityNotFoundException
     * @throws OtpNotValidException
     * @throws OtpExpiredException
     */
    Boolean reIssueLegacyXMLCertificate(EntityInfo entityInfo, String certificateLocation, Boolean certificateChain, String passwordLocation, final CrlReason revocationReason)
            throws ReIssueLegacyXMLCertificateException, EntityNotFoundException, OtpNotValidException, OtpExpiredException;

}
