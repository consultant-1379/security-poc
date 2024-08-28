/*------------------------------------------------------------------------------
 *******************************************************************************
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
package com.ericsson.oss.itpf.security.credmsapi.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.*;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateSummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntitySummary;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;

public interface IfCertificateManagement {

    /**
     * getCredentialManagerInterfaceVersion
     * 
     * @return
     */
    String getCredentialManagerInterfaceVersion();

    /**
     * Method invoked by the Auto Provisioning for ENIS operator, It sends a certificate request to the credential manager server. (without CRL info)
     * 
     * @param entityInfo
     *            containing entity name and OTP for ENIS operator
     * @param ksInfo
     *            representing a collection of informations related to the Key Store
     * @return true if the operation is successful
     * 
     * @throws IssueCertificateException
     *             thrown when a generic error occurs during certificate issuing
     * @throws EntityNotFoundException
     *             thrown when the specified entity is not found in PKI System
     * @throws InvalidCertificateFormatException
     *             thrown when the certificate format is not valid (only PKCS12 allowed)
     */
    Boolean issueCertificate(EntityInfo entityInfo, KeystoreInfo ksInfo) throws IssueCertificateException, EntityNotFoundException, InvalidCertificateFormatException, OtpNotValidException,
            OtpExpiredException;

    /**
     * The method sends a certificate reissue request to the credential manager server, that functionality implies, internally, a revocation and rekey followed by an issue.
     * 
     * @param entityInfo
     *            containing entity name and OTP for ENIS operator
     * @param ksInfo
     *            representing a collection of informations related to the Key Store
     * @param revocationReason
     *            is an enumeration following the RFC 5280 specification
     * @return true if the operation is successful
     * 
     * @throws IssueCertificateException
     *             thrown when a generic error occurs during certificate issuing
     * @throws EntityNotFoundException
     *             thrown when the specified entity is not found in PKI System
     * @throws InvalidCertificateFormatException
     *             thrown when the certificate format is not valid (only PKCS12 allowed)
     * 
     */
    Boolean reIssueCertificate(EntityInfo entityInfo, KeystoreInfo ksInfo, CrlReason revocationReason) throws ReissueCertificateException, EntityNotFoundException, InvalidCertificateFormatException,
            OtpNotValidException, OtpExpiredException;
    
    /**
     * Method invoked by SLS in order to reissue a certificate in legacy XML format 
     * for AMOS and EM applications.
     * 
     * @param entityInfo
     *            containing entity name and OTP for ENIS operator
     * @param certificateLocation
     *            representing  the location path for output XML certificate
     * @param certificateChain
     *            boolean indicating if chain is required or not for the certificate (must be not null)
     * @param passwordLocation   
     *            representing the location path for the file containing the password for encrypting 
     *            the private key: if null or empty then the (default) password is taken from internal file 
     * @param revocationReason
     *            is an enumeration following the RFC 5280 specification
     * @return true if the operation is successful
     * 
     * @throws ReIssueLegacyXMLCertificateException
     *             thrown when a generic error occurs during certificate reissuing
     * @throws EntityNotFoundException
     *             thrown when the specified entity is not found in PKI System
     * @throws OtpNotValidException
     *             thrown when the OTP is not valid
     * @throws OtpExpiredException
     *             thrown when the OTP is expired
     */


    Boolean reIssueLegacyXMLCertificate (EntityInfo entityInfo, String certificateLocation, Boolean certificateChain, String passwordLocation, final CrlReason revocationReason)
    		throws ReIssueLegacyXMLCertificateException, EntityNotFoundException, OtpNotValidException, OtpExpiredException;


    /**
     * The method sends a certificate revocation request to the credential manager server.
     * 
     * @param entityInfo
     *            containing entity name and OTP for ENIS operator
     * @param revocationReason
     *            boolean isCertificateValid(X509C)
     * 
     *            is an enumeration following the RFC 5280 specification
     * 
     * @return true if the operation is successful
     * 
     * @throws RevokeCertificateException
     *             thrown when a generic error occurs during certificate revoking
     * @throws EntityNotFoundException
     *             thrown when the specified entity is not found in PKI System
     * 
     */
    Boolean revokeCertificate(EntityInfo entityInfo, CrlReason revocationReason) throws RevokeCertificateException, EntityNotFoundException;

    /**
     * getEndEntitiesByCategory
     * 
     * API used to return a list of database entries (end entities) given the input category (e.g. Users given "SLSUsers" category) it may return an empty list if no end entities are found inside the
     * PKI DB with the specified category
     * 
     * @param entity
     *            category
     * 
     * @return List<EntitySummary>
     * 
     * @throws GetEndEntitiesByCategoryException
     *             thrown when InternalServiceException is caught (usually CredM Service or PKI DB connection problems)
     * @throws InvalidCategoryNameException
     *             thrown when category name passed as parameter is not allowed by CredM Service
     * 
     */
    List<EntitySummary> getEndEntitiesByCategory(String category) throws GetEndEntitiesByCategoryException, InvalidCategoryNameException;

    /**
     * getCertificatesByEntityName
     * 
     * API used to return a list of certificateSummary for input entityName of given EntityType and having input certificate status(es).
     * 
     * @param entityName
     *            The entity name.
     * @param entityType
     *            The entity type.
     * @param certificateStatus
     *            The certificate status (can be more than one).
     * 
     * @return List<CertificateSummary>
     * 
     * @throws CertificateNotFoundException
     *             Thrown in case of entity does not have certificate(s) for the given status(es).
     * @throws GetCertificatesByEntityNameException
     *             Thrown in case of any database/services errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown in case of given Entity of given type does not exist
     */
    List<CertificateSummary> getCertificatesByEntityName(String entityName, EntityType entityType, CertificateStatus... certificateStatus) throws CertificateNotFoundException,
            GetCertificatesByEntityNameException, EntityNotFoundException;

    /**
     * revokeEntityCertificate
     * 
     * API used to revoke the particular certificate which is identified by inputs: issuerDN, subjectDN, certificateSN
     * 
     * @param issuerDN
     *            contains issuer DN of the certificate to be revoked.
     * @param subjectDn
     *            contains subject DN of the certificate to be revoked.
     * @param serialNumber
     *            contains serialNumber of the certificate to be revoked.
     * @param revocationReason
     *            reason for revoking the certificate.
     * 
     * @return true if the operation is successful
     * 
     * @throws CertificateNotFoundException
     *             thrown when certificate is not present.
     * @throws ExpiredCertificateException
     *             thrown when revocation is requested for an expired certificate.
     * @throws AlreadyRevokedCertificateException
     *             thrown when revocation is requested for an already revoked certificate.
     * @throws RevokeEntityCertificateException
     *             thrown to indicate any internal database/services errors or any unconditional exceptions occurs during the revocation of a Certificate.
     * 
     */
    Boolean revokeEntityCertificate(String issuerDN, String subjectDN, String certificateSN, CrlReason revocationReason) throws CertificateNotFoundException, ExpiredCertificateException,
            AlreadyRevokedCertificateException, RevokeEntityCertificateException;

}