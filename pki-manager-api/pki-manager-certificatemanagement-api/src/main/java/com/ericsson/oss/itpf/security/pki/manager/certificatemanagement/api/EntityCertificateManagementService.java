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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.InvalidCertificateStatusException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

/**
 * This interface is for Entity certificate management and provides for below operations.
 * <ul>
 * <li>Generating certificates for Entities.</li>
 * <li>Updating certificates for Entities.</li>
 * </ul>
 */

@EService
@Remote
public interface EntityCertificateManagementService extends CertificateManagementService {

    /**
     * This method is for creation of certificates for entities with PKCS10 Request or CRMF Request.
     * 
     * @param entityName
     *            name of the entity for which certificate needs to be generated.
     * @param certificateRequest
     *            {@link CertificateRequest} holder object containing PKCS10 request or CRMF Request.
     * @return Certificate generated for the given Entity.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidCertificateRequestException
     *             Thrown to indicate that the given Certificate Request is not valid.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, RevokedCertificateException;

    /**
     * This method is for creation of certificates for entities with PKCS10 Request or CRMF Request along with otp validation.
     * 
     * @param entityName
     *            name of the entity for which certificate needs to be generated.
     * @param certificateRequest
     *            {@link CertificateRequest} holder object containing PKCS10 request or CRMF Request.
     * @param otp
     *            one time password for the entity for authentication
     * 
     * @return Certificate generated for the given Entity.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidCertificateRequestException
     *             Thrown to indicate that the given Certificate Request is not valid.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0 and existing OTP is no longer valid
     * @throws InvalidOTPException
     *             thrown when OTP provided does not match
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    Certificate generateCertificate(final String entityName, final CertificateRequest certificateRequest, final String otp) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException,
            InvalidEntityAttributeException, OTPExpiredException, InvalidOTPException, RevokedCertificateException;

    /**
     * This method is for creation of certificates for entities without CertificateRequest. In this case CertificateRequest will be generated in PKI Manager and passed to PKI Core.
     * 
     * @param entityName
     *            Name of the Entity for which certificate needs to be generated.
     * @param password
     *            Contains the password to protect the Key contained in the KeyStore
     * @param KeyStoreType
     *            KeyStore types that are supported in the system.
     * @return KeyStoreInfo object containing the KeyStore object, alias name of the Key and password.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    KeyStoreInfo generateCertificate(final String entityName, final char[] password, final KeyStoreType keyStoreType) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException;

    /**
     * This method is for Updating entity certificate with a PKCS10 request or CRMF Request. This method needs to be used only in case of certificate renewal and certificate modification.
     * 
     * @param entityName
     *            name of the entity for which certificate needs to be generated.
     * @param certificateRequest
     *            CertificateRequest holder object containing PKCS10 request or CRMF Request.
     * @param updateType
     *            Type of the update request. Type can be RENEW and MODIFY only
     * @return Certificate the updated certificate
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidCertificateRequestException
     *             Thrown to indicate that the given Certificate Request is not valid.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    Certificate renewCertificate(final String entityName, final CertificateRequest certificateRequest) throws AlgorithmNotFoundException, CertificateGenerationException, CertificateServiceException,
            EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidCertificateRequestException, InvalidEntityException, InvalidEntityAttributeException,
            RevokedCertificateException;

    /**
     * Updates entity certificate without CertificateRequest. In this case CertificateRequest will be generated in PKI Manager and passed on to PKI Core. This method should be used only in case of
     * rekey.
     * 
     * @param entityName
     *            name of the entity for which certificate needs to be generated.
     * @param password
     *            Contains the password to protect the Key contained in the KeyStore
     * @param KeyStoreType
     *            KeyStore types that are supported in the system.
     * @param updateType
     *            type of the update for the certificate. Allowed value in this method is only REKEY
     * @return KeyStoreInfo object containing path of key store file, alias name and password.
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while certificate generation.
     * @throws EntityNotFoundException
     *             Thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case the given Entity does not have a valid issuer.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    KeyStoreInfo reKeyCertificate(final String entityName, final char[] password, final KeyStoreType keyStoreType) throws AlgorithmNotFoundException, CertificateGenerationException,
            CertificateServiceException, EntityNotFoundException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException;

    /**
     * Returns entity's Active certificate chain.
     * 
     * @param entityName
     *            name of the Entity
     * @return CertificateChain Return complete chain of certificates from Entity to RootCA.
     * 
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while getting certificate chain.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidCertificateStatusException
     *             Thrown when the Certificate Status is invalid to get the Certificate Chain.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not found or doesn't have any valid certificate.
     * @throws InvalidEntityAttributeException
     *             Thrown in case of the given entity has invalid attribute.
     */
    CertificateChain getCertificateChain(final String entityName) throws CertificateServiceException, InvalidCAException, InvalidCertificateStatusException, InvalidEntityException,
            InvalidEntityAttributeException;

    /**
     * Returns list of certificateChains {@link CertificateChain} of active and/or inactive certificates of Entity based on the status. Returns Returns list of certificateChains
     * {@link CertificateChain} of both active and inactive certificates of CAEntity if certificateStatus is null or empty.
     * 
     * @param entityName
     *            name of the Entity
     * @param certificateStatus
     *            certificateStatus {@link CertificateStatus} contains Active or InActive or both.
     * @return certificateChains list of complete chain of certificates from Entity to RootCA.
     * 
     * @throws CertificateServiceException
     *             Thrown when internal db error occurs while getting certificate chain list.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidCertificateStatusException
     *             Thrown when the Certificate Status is invalid to get the Certificate Chain.
     * @throws InvalidEntityException
     *             Thrown in case the given Entity is not found or doesn't have any valid certificate.
     * @throws InvalidEntityAttributeException
     *             Thrown in case the given Entity has invalid attribute.
     */
    List<CertificateChain> getCertificateChainList(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException, InvalidCAException,
            InvalidCertificateStatusException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * This implementation need to be align with the latest object model and this will be covered in the user story TORF-63444.
     * 
     * Return entity's trust CA certificates
     * 
     * @param entityName
     *            Name of the entity for which trust CA certificates are mapped to.
     * @return List<Certificate> List of Trusted Certificate Objects. List of active certificate of the Trusted CA's for a given entity.
     * 
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions while retrieving the trust profile for a given entity.
     * @throws EntityNotFoundException
     *             Thrown when the given entity doesn't exists.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws InvalidCAException
     *             Thrown in case the trusted CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws ProfileNotFoundException
     *             Thrown when there is no trust profile found for a given entity name.
     */
    List<Certificate> getTrustCertificates(final String entityName) throws CertificateServiceException, EntityNotFoundException, ExternalCredentialMgmtServiceException, InvalidCAException,
            InvalidEntityAttributeException, ProfileNotFoundException;

    /**
     * This API method will publish the certificate for a given entity name to Trust distribution service based on CA Name and certificateStatus.
     * 
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     * 
     * @throws CertificateServiceException
     *             Thrown in case there are any internal errors while fetching entity/certificate or dispatching event. All internal exceptions are wrapped to this high level exception.
     * 
     * @throws EntityNotFoundException
     *             Thrown in case entity is not found with the given name
     */
    void publishCertificate(final String entityName) throws CertificateServiceException, EntityNotFoundException;

    /**
     * This API method will un-publish the certificate for a given entity Name to Trust distribution point service.
     * 
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     * 
     * @throws CertificateServiceException
     *             Thrown in case there are any internal errors while fetching entity/certificate or dispatching event. All internal exceptions are wrapped to this high level exception.
     * 
     * @throws EntityNotFoundException
     *             Thrown in case entity is not found with the given name
     */
    void unPublishCertificate(final String entityName) throws CertificateServiceException, EntityNotFoundException;

    // TODO:TORF-85221 for List certificates for Webcli command

    /**
     * This method will perform the chain validation for the given entity certificate with the given serial number and issuer name. Returns true if the certificate is a valid. Return false if 1. The
     * entity does not have any certificate. 2. No active certificate found with the given serial number and issuer name. 3. The entity certificate with given serial number and issuer name has an
     * invalid certificate chain. This chain validation ensures that all the certificates in the certificate chain should be in ACTIVE state.
     * 
     * @param entityName
     *            Name of the entity whose certificate need to be validated.
     * @param serialNumber
     *            Serial number of the entity certificate which has to be validated.
     * @param issuerName
     *            Issuer name for the given certificate.
     * @return True if the certificate is valid, false otherwise.
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown in case of given Entity does not exists.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity is not valid.
     */
    boolean isValidCertificate(final String entityName, final String serialNumber, final String issuerDN) throws CertificateServiceException, EntityNotFoundException,
    InvalidEntityAttributeException;

    /**
     * This method will check if the certificate exists in the PKI with the given subjectDN, serialNumber and issued by the given issuerDN.
     *
     * @param subjectDN
     *            subjectDN whose certificate need to be validated.
     * @param serialNumber
     *            Serial number of the entity certificate which has to be validated.
     * @param issuerDN
     *            issuerDN whose certificate need to be validated.
     * @return True if the certificate is valid, false otherwise.
     * @throws CertificateServiceException
     *             Throws in case of any database errors or any unconditional exceptions.
     */
    boolean isCertificateExist(final String subjectDN, final String serialNumber, final String issuerDN) throws CertificateServiceException;
}
