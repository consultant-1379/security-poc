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

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCRLServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateEncodingException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateExsitsException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidCSRException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidEntityException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidProfileException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerProfileNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;


/**
 * (PRELIMINARY) This is an interface for credential management service and provides API's for below operations.
 * <ul>
 * <li>Create or Get Entity.</li>
 * <li>Get Entity.</li>
 * <li>Get EntityProfile.</li>
 * <li>Get Certificate for an Entity</li>
 * <li>Get Trust CA Certificates for an EntityProfile</li>
 * </ul>
 */

@Remote
public interface CredMService {

    
    
    /**
     * Used only for test. It will be removed before release it to the customer.
     * 
     * @param msg
     *            the name of the client.
     * @return a welcome string.
     */
    String hello(String msg);

    /**
     * 
     * @return the EJB interface version
     */
    String getVersion();

    /**
     * (PRELIMINARY) This method creates an Entity if it doesn't exist, otherwise it updates the Entity information. It returns the new Entity information.
     * 
     * @param entityName
     *            the name of the Entity
     * @param subject
     *            the certificate subject of the Entity
     * @param subjectAltName
     *            the certificate subject alternative name of the EndEntity
     * @param keyGeneretionAlgorithm
     *            the key generation algorithm of the Entity keys.
     * @param entityProfileName
     *            the Entity profile name of the EEntity
     * @return Returns object of CredentialManagerEntity class containing the Entity information.
     * @throws CredentialManagerInvalidEntityException
     *             Thrown if the PKI entity is not well formed.
     * @throws CredentialManagerInternalServiceException
     *             Thrown if PKI replays with a InternalServiceException
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerProfileNotFoundException
     *             Thrown if the profile is not present.
     */
    CredentialManagerEntity createAndGetEntity(String entityName, CredentialManagerSubject subject, CredentialManagerSubjectAltName subjectAltName, CredentialManagerAlgorithm keyGenerationAlgorithm,
            String entityProfileName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException,
            CredentialManagerProfileNotFoundException;

    /**
     * (PRELIMINARY) This method returns the Entity information.
     * 
     * @param entityName
     *            the name of the Entity
     * @return Returns object of CredentialManagerEntity class containing the Entity information, if some errors occurred null is returned.
     * @throws CredentialManagerInvalidEntityException
     *             Thrown if the entity returned by PKI is not well formed.
     * @throws CredentialManagerEntityNotFoundException
     *             Thrown in case the given entity does not exist
     * @throws CredentialManagerInternalServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityName is empty).
     */
    CredentialManagerEntity getEntity(String entityName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerEntityNotFoundException,
            CredentialManagerInvalidEntityException;

    /**
     * (PRELIMINARY) This method returns the Entity Profile and its own Certificate Profile information.
     * 
     * @param entityProfileName
     *            the name of the EndEntity profile.
     * @return Returns object of CredentialManagerProfileInfo class containing the Entity Profile and Certificate Profile information, if some error occurred null is returned.
     * @throws CredentialManagerProfileNotFoundException
     *             Thrown in case the given profile does not exist
     * @throws CredentialManagerInternalServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityName is empty).
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     */
    CredentialManagerProfileInfo getProfile(String entityProfileName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException;

    /**
     * (PRELIMINARY) This method generates a certificate from a CertificateSignRequest. This certificate will be signed with the issuer private key.
     * 
     * @param csr
     *            the BouncyCastle CSR (PKCS10CertificationRequest) wrapped in a serializable class.
     * @param entityName
     *            the Name of the entity for which the certificate is request.
     * @param certificateChain
     *            the flag telling if it is necessary to retrieve the complete certificate chain or not.
     * @return Returns object of CredentialManagerX509Certificate class containing a X509Certificate, if some error occurred null is returned.
     * @throws CredentialManagerCertificateEncodingException
     *             Thrown when the certificate returned from PKI is not well formed.
     * @throws CredentialManagerCertificateExsitsException
     *             Thrown if there is already certificate for given entity.
     * @throws CredentialManagerInvalidEntityException
     *             Thrown when the given Entity is incomplete.
     * @throws CredentialManagerInvalidCSRException
     *             Thrown when the given CSR is invalid.
     * @throws CredentialManagerCertificateGenerationException
     *             Thrown in case of any exception while generating the certificate.
     * @throws CredentialManagerEntityNotFoundException
     *             Thrown in case the given entity does not exist
     */
    CredentialManagerX509Certificate[] getCertificate(CredentialManagerPKCS10CertRequest csr, String entityName, boolean certificateChain, String otp)
            throws CredentialManagerCertificateEncodingException, CredentialManagerEntityNotFoundException, CredentialManagerCertificateGenerationException, CredentialManagerInvalidCSRException,
            CredentialManagerInvalidEntityException, CredentialManagerCertificateExsitsException;

    /**
     * (PRELIMINARY) This method returns a map with the CAs Certificate Chain present into the Trust profile associated with the EndEntity profile.
     * 
     * @param entityProfileName
     *            the name of the Entity profile.
     * @return Returns a map of CredentialManagerCertificateAuthority class containing the Certificate chain of the CAs.
     * @throws CredentialManagerProfileNotFoundException
     *             Thrown in case the given profile does not exist.
     * @throws CredentialManagerInternalServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerCertificateEncodingException
     *             Thrown when the certificate returned from PKI is not well formed.
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     */
    CredentialManagerTrustMaps getTrustCertificates(String profileName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException;

    /**
     * version of getTrustCertificates using TrustProfile
     * 
     * @param trustProfileName
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInternalServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerCertificateEncodingException
     * @throws CredentialManagerInvalidProfileException
     */
    CredentialManagerTrustMaps getTrustCertificatesTP(String trustProfileName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException;

    /**
     * (PRELIMINARY) This method receives a trustMap and compare the certificates with the certificate identifiers contained in currentTrustIdentifiers. If the comparison fail then returns a map with
     * the CAs Certificate Chain present into the Trust profile associated with the EndEntity profile. Otherwise return null.
     * 
     * @param CredentialManagerCertificateAuthority
     *            the name of the Entity profile.
     * @param currentTrustIdentifiers
     *            the list of CredentialManagerCertificateIdentifier contained in the current trust store
     * @param internalFlag
     * 
     * @param boolean externalFlag
     * 
     * @return Returns a boolean with the result of comparison.
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerCertificateEncodingException
     *             Thrown when the certificate returned from PKI is not well formed.
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     */
    CredentialManagerTrustMaps compareTrustAndRetrieve(final String profileName, final SortedSet<CredentialManagerCertificateIdentifier> trustIdentifiers, final boolean internalFlag,
            final boolean externalFlag) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException;

    /**
     * version of compareTrustAndRetrieve using TrustProfile
     * 
     * @param trustProfileName
     * @param trustIdentifiers
     * @param internalFlag
     * @param externalFlag
     * @return
     * @throws CredentialManagerInvalidArgumentException
     * @throws CredentialManagerInternalServiceException
     * @throws CredentialManagerProfileNotFoundException
     * @throws CredentialManagerCertificateEncodingException
     * @throws CredentialManagerInvalidProfileException
     */
    CredentialManagerTrustMaps compareTrustAndRetrieveTP(final String trustProfileName, final SortedSet<CredentialManagerCertificateIdentifier> trustIdentifiers, final boolean internalFlag,
            final boolean externalFlag) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerProfileNotFoundException,
            CredentialManagerCertificateEncodingException, CredentialManagerInvalidProfileException;

    /**
     * (PRELIMINARY) This method returns a map with the CAs CRL included in the Trust profile associated with the EndEntity
     * 
     * @param entityProfileName
     *            the name of the Entity profile.
     * @param isChainRequired
     * @param clrIdentifiers
     * 
     * @return Returns a map of CredentialManagerX509CRL class containing the CRL for the CAs
     * @throws CredentialManagerInternalServiceException
     *             Thrown in case of an internal error
     * @throws CredentialManagerInternalServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     * @throws CredentialManagerCRLEncodingException
     *             Thrown when the crl returned from PKI is not well formed.
     * @throws CredentialManagerCRLServiceException
     *             Thrown if the crls for external EPPKI are not found.
     * @throws CredentialManagerCertificateServiceException
     *             Thrown if the PKI CRL management is not implemented.
     */
    CredentialManagerCrlMaps getCRLs(String entityProfileName, boolean isChainRequired) throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException;

    /**
     * version of getCRLs using TrustProfile
     * 
     * @param trustName
     *            the name of the Trust profile.
     * @param isChainRequired
     * @param clrIdentifiers
     * 
     * @return Returns a map of CredentialManagerX509CRL class containing the CRL for the CAs
     * @throws CredentialManagerInternalServiceException
     *             Thrown in case of an internal error
     * @throws CredentialManagerInternalServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     * @throws CredentialManagerCRLEncodingException
     *             Thrown when the crl returned from PKI is not well formed.
     * @throws CredentialManagerCRLServiceException
     *             Thrown if the crls for external EPPKI are not found.
     * @throws CredentialManagerCertificateServiceException
     *             Thrown if the PKI CRL management is not implemented.
     */
    CredentialManagerCrlMaps getCRLsTP(String entityProfileName, boolean isChainRequired) throws CredentialManagerInvalidArgumentException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerCertificateServiceException, CredentialManagerCRLServiceException,
            CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException;

    /**
     * (PRELIMINARY) This method returns a map with the CAs CRL included requested for related Entity
     * 
     * @param entityProfileName
     *            the name of the Entity.
     * @param isChainRequired
     * 
     * @return Returns a map of CredentialManagerX509CRL class containing the CRL for the CAs
     * 
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerCertificateServiceException
     *             Thrown if the PKI CRL management is not implemented.
     * @throws CredentialManagerServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerProfileNotFoundException
     *             Thrown in case the given profile does not exist.
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     * @throws CredentialManagerCRLEncodingException
     *             Thrown when the crl returned from PKI is not well formed.
     * @throws CredentialManagerCRLServiceException
     *             Thrown if the crls for external EPPKI are not found.
     */
    CredentialManagerCrlMaps compareCrlsAndRetrieve(String entityProfileName, boolean isChainRequired, final SortedSet<CredentialManagerCRLIdentifier> currentClrIdentifiers,
            final boolean internalFlag, final boolean externalFlag) throws CredentialManagerInvalidArgumentException, CredentialManagerCertificateServiceException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException;

    /**
     * version of compareCrlsAndRetrieve using Trust profile
     * 
     * @param trustName
     *            the name of the Trust profile.
     * @param isChainRequired
     * 
     * @return Returns a map of CredentialManagerX509CRL class containing the CRL for the CAs
     * 
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityProfileName is empty).
     * @throws CredentialManagerCertificateServiceException
     *             Thrown if the PKI CRL management is not implemented.
     * @throws CredentialManagerServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws CredentialManagerProfileNotFoundException
     *             Thrown in case the given profile does not exist.
     * @throws CredentialManagerInvalidProfileException
     *             Thrown if the profile returned by PKI is not well formed.
     * @throws CredentialManagerCRLEncodingException
     *             Thrown when the crl returned from PKI is not well formed.
     * @throws CredentialManagerCRLServiceException
     *             Thrown if the crls for external EPPKI are not found.
     */
    CredentialManagerCrlMaps compareCrlsAndRetrieveTP(String trustName, boolean isChainRequired, final SortedSet<CredentialManagerCRLIdentifier> currentClrIdentifiers, final boolean internalFlag,
            final boolean externalFlag) throws CredentialManagerInvalidArgumentException, CredentialManagerCertificateServiceException, CredentialManagerServiceException,
            CredentialManagerProfileNotFoundException, CredentialManagerInvalidProfileException, CredentialManagerCRLServiceException, CredentialManagerCRLEncodingException;

    /**
     * (PRELIMINARY) This method creates an Entity. It returns the new Entity information.
     * 
     * @param entityName
     *            the name of the Entity
     * @param subject
     *            the certificate subject of the Entity
     * @param subjectAltName
     *            the certificate subject alternative name of the EndEntity
     * @param keyGeneretionAlgorithm
     *            the key generation algorithm of the Entity keys.
     * @param entityProfileName
     *            the Entity profile name of the Entity
     * @return Returns object of CredentialManagerEntity class containing the Entity information, if some errors occurred null is returned.
     * @throws CredentialManagerInvalidEntityException
     *             Thrown returned if the PKI entity is not well formed
     * @throws CredentialManagerInternalServiceException
     *             Thrown if PKI replays with a InternalServiceException
     * @throws CredentialManagerInvalidArgumentException
     *             Thrown if at least a given parameter is invalid (i.e. entityName is empty).
     */
    CredentialManagerEntity createEntity(String entityName, CredentialManagerSubject subject, CredentialManagerSubjectAltName subjectAltName, CredentialManagerAlgorithm keyGenerationAlgorithm,
            String entityProfileName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException, CredentialManagerInvalidEntityException;

    /**
     * getEntitiesByCategory
     * 
     * @param categoryName
     * @return set of CredentialManagerEntity (if there are no entities for this category an empty set is returned)
     * 
     * @throws CredentialManagerInvalidArgumentException
     *             if the category doesn't exist
     * @throws CredentialManagerInternalServiceException
     *             for any other reason
     */
    Set<CredentialManagerEntity> getEntitiesByCategory(String categoryName) throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException;

    /**
     * isOTPValid
     * 
     * @param entityName
     * @param otp
     * @return
     * @throws CredentialManagerEntityNotFoundException
     * @throws CredentialManagerOtpExpiredException
     * @throws CredentialManagerInternalServiceException
     */
    boolean isOTPValid(String entityName, String otp) throws CredentialManagerEntityNotFoundException, CredentialManagerOtpExpiredException, CredentialManagerInternalServiceException;

    /**
     * revokeCertificateByEntity
     * 
     * @param entityName
     * @param reason
     * @param invalidityDate
     * 
     * @throw CredentialManagerInternalServiceException
     * @throw CredentialManagerEntityNotFoundException
     */
    void revokeCertificateByEntity(final String entityName, CredentialManagerRevocationReason reason, Date invalidityDate) throws CredentialManagerInternalServiceException,
            CredentialManagerEntityNotFoundException;

    /**
     * revokeCertificateByCertId
     * 
     * @param certificateIdentifier
     * @param reason
     * @param invalidityDate
     * @throw CredentialManagerInternalServiceException
     * @throw CredentialManagerCertificateNotFoundException
     * @throw CredentialManagerExpiredCertificateException
     * @throw CredentialManagerAlreadyRevokedCertificateException
     */
    void revokeCertificateById(final CredentialManagerCertificateIdentifier certificateIdentifer, final CredentialManagerRevocationReason reason, final Date invalidityDate)
            throws CredentialManagerInternalServiceException, CredentialManagerCertificateNotFoundException, CredentialManagerExpiredCertificateException,
            CredentialManagerAlreadyRevokedCertificateException;

    /**
     * listCertificates
     * 
     * @param entityName
     * @param entityType
     * @param certsStatus
     * @throw CredentialManagerInternalServiceException
     */
    List<CredentialManagerX509Certificate> listCertificates(final String entityName, final CredentialManagerEntityType entityType, final CredentialManagerCertificateStatus... certsStatus)
            throws CredentialManagerInternalServiceException;

    /**
     * printCommandOnRecorder Prints a command using SystemRecorderWrapper class
     * 
     * @param message
     *            message to be printed
     * @param category
     *            Classifies the category of the message type
     * @param source
     *            Defines the source (artifact/package) from which the message arrived
     * @param entityName
     *            End Entity or CA involved
     * @param infos
     *            Additional Infos
     * @throws IllegalArgumentException
     */
    void printCommandOnRecorder(final String message, final CommandPhase category, final String source, final String entityName, final String infos) throws IllegalArgumentException;

    /**
     * printErrorOnRecorder Prints a command using SystemRecorderWrapper class
     * 
     * @param message
     *            message to be printed
     * @param category
     *            Classifies the category of the message type
     * @param source
     *            Defines the source (artifact/package) from which the message arrived
     * @param entityName
     *            End Entity or CA involved
     * @param infos
     *            Additional Infos
     * @throws IllegalArgumentException
     */
    void printErrorOnRecorder(final String message, final ErrorSeverity category, final String source, final String entityName, final String infos) throws IllegalArgumentException;

    /**
     * getPibParameters Return pib parameter
     * 
     * @return Returns CredentialManagerPIBParameters object
     */
    public CredentialManagerPIBParameters getPibParameters();

    /**
     * listCertificatesSummary
     * 
     * @param entityName
     *            name of the Entity/CaEntity
     * @param entityType
     *            entity Type
     * @param certsStatus
     *            status(es) of the certificate(s) to be retrieved
     * 
     * @throw CredentialManagerInternalServiceException
     * @throw CredentialManagerCertificateNotFoundException
     * @throw CredentialManagerEntityNotFoundException
     */
    List<CredentialManagerX500CertificateSummary> listCertificatesSummary(String entityName, CredentialManagerEntityType entityType, CredentialManagerCertificateStatus... credMCertStatus)
            throws CredentialManagerCertificateNotFoundException, CredentialManagerEntityNotFoundException, CredentialManagerInternalServiceException;

    /**
     * getEntitiesSummaryByCategory
     * 
     * @param categoryName
     * @return set of CredentialManagerEntity (if there are no entities for this category an empty set is returned)
     * 
     * @throws CredentialManagerInvalidArgumentException
     *             if the category doesn't exist
     * @throws CredentialManagerInternalServiceException
     *             for any other reason
     */
    Set<CredentialManagerEntity> getEntitiesSummaryByCategory(String categoryName)
            throws CredentialManagerInvalidArgumentException, CredentialManagerInternalServiceException;

}
