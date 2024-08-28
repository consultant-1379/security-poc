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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.CAReIssueInfo;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.*;

/**
 * This is an interface for CAEntity certificate management service and it provides below operations.
 * <ul>
 * <li>Generating certificates for CA entities.</li>
 * <li>Renew, Modification and Rekey operations of CA entities.</li>
 * <li>Exporting CSR of CA.</li>
 * <li>Importing CA certificate.</li>
 * </ul>
 */
@EService
@Remote
public interface CACertificateManagementService extends CertificateManagementService {

    /**
     * This method will create certificate for CAEntity. For CAEntity CSR will be generated in PKI core. From the entity name, we can get the entity profile and corresponding certificate profile
     * objects. From these profiles and CSR, certificate is generated.
     * 
     * @param entityName
     *            The CA entity name.
     * @return {@link Certificate}.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    Certificate generateCertificate(final String entityName) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityAttributeException, RevokedCertificateException;

    /**
     * This method supports renew and modification of the given CA entity certificate. It generates ACTIVE certificate of CA with or without change of certificate information. It would update the
     * existing certificate as INACTIVE.
     * 
     * @param cAName
     *            name of the CA entity.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    void renewCertificate(String cAName, ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException;

    /**
     * This method supports renewal of certificates for multiple CA certificates at a time. It generates ACTIVE certificate for each CA. It would update the existing certificates as INACTIVE.
     * 
     * @param cANames
     *            set of CA entity names
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown if expired certificate is found in the certificate chain of the certificate issuer.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws RevokedCertificateException
     *             Thrown if revoked certificate is found in the certificate chain of the certificate issuer.
     */
    void renewCertificates(Set<String> cANames) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException, ExpiredCertificateException,
            InvalidCAException, RevokedCertificateException;

    /**
     * Supports renewal and modification of the given CA certificate. It generates ACTIVE certificate for the given CA and revokes existing certificate. Ignores if already revoked.
     * 
     * @param caReIssueInfo
     *            model that contains parameters required for CA renewal/rekey and revocation of existing certificate.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateNotFoundException
     *             Thrown in case certificate does not exist for the given CA Entity.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             Thrown when the user provided InvalidityDate is beyond the certificate Validity during certificate revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     */
    void renewCertificate(CAReIssueInfo caReIssueInfo, ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException,
            IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException;

    /**
     * Supports renewal or modification of multiple CA certificates. It generates ACTIVE certificate for each CA and revokes existing certificate.
     * 
     * @param caReIssueInfoList
     *            list of models that contains parameters required for CA renewal/rekey and revocation of existing certificate..
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * @throws CANotFoundException
     *             Thrown when given CA(s) doesn't exists.
     * @throws CertificateGenerationException
     *             Thrown to indicate that an exception has occurred during certificate generation.
     * @throws CertificateNotFoundException
     *             Thrown in case certificate does not exist for the given CA Entity.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws ExpiredCertificateException
     *             Thrown if expired certificate is found in the certificate chain of the certificate issuer.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws RevokedCertificateException
     *             Thrown if revoked certificate is found in the certificate chain of the certificate issuer.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     */
    void renewCertificates(List<CAReIssueInfo> caReIssueInfoList) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException;

    /**
     * This method supports rekey operation for the CA. It generates ACTIVE key pair and certificate for the given CA. It would update existing certificate to INACTIVE.
     * 
     * @param entityName
     *            name of CA Entity.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm does not exist in the database.
     * @throws CANotFoundException
     *             Thrown when given CA not found in the database.
     * @throws CertificateGenerationException
     *             Thrown when failure occurs generating the certificate for the CA Entity.
     * @throws CertificateServiceException
     *             Thrown in case any failure occurs with certificate generation.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    void rekeyCertificate(String entityName, ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateServiceException,
            ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, RevokedCertificateException;

    /**
     * This method supports rekey operation for the CA. It generates ACTIVE key pair, certificate for the given CA and revokes existing certificate. Ignores if already revoked.
     * 
     * @param caReIssueInfo
     *            The caReIssueInfo object contains the CAName and revocation details.
     * @param reIssueType
     *            type that specifies renew operation should be done for single CA or CA with its child's or CA and its chain.
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm does not exist in the database.
     * @throws CANotFoundException
     *             Thrown when given CA not found in the database.
     * @throws CertificateGenerationException
     *             Thrown when failure occurs generating the certificate for the CA Entity.
     * @throws CertificateNotFoundException
     *             Thrown in case certificate does not exist for the given CA Entity.
     * @throws CertificateServiceException
     *             Thrown in case any failure occurs with certificate generation.
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidEntityException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             Thrown when the user provided InvalidityDate is beyond the certificate Validity during certificate revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     */
    void rekeyCertificate(CAReIssueInfo caReIssueInfo, ReIssueType reIssueType) throws AlgorithmNotFoundException, CANotFoundException, CertificateGenerationException, CertificateNotFoundException,
            CertificateServiceException, ExpiredCertificateException, InvalidCAException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException,
            IssuerCertificateRevokedException, RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException;

    /**
     * Returns the CSR for a given CAEntity based on the newKey flag. If newKey flag is set to true, then CSR is generated using a new KeyPair. Otherwise CSR is generated with existing KeyPair and
     * will be returned
     * 
     * @param entityName
     *            name of the CAEntity for which CSR needs to be generated.
     * @param newKey
     *            Flag basing on which, it will be decided if the CSR has to be generated with a new KeyPair
     * @return PKCS10CertificationRequestHolder object containing PKCS10 certification request in byte form.
     * @throws AlgorithmNotFoundException
     *             Thrown when the algorithm is not found
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateRequestGenerationException
     *             Thrown when CertificateRequest generation or export is failed.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws InvalidEntityException
     *             Thrown when the given entity has invalid attribute.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     */
    PKCS10CertificationRequestHolder generateCSR(final String entityName, final boolean newKey) throws AlgorithmNotFoundException, CANotFoundException, CertificateRequestGenerationException,
            CertificateServiceException, InvalidCAException, InvalidEntityAttributeException;

    /**
     * This method is used to fetch latest CSR for the given CA from the database.
     * 
     * @param caName
     *            for which latest CSR has to be fetched.
     * @return CSR in PKCS10CertificationRequestHolder object.
     * @throws CANotFoundException
     *             is thrown if given CA is not found in the database.
     * @throws CertificateRequestGenerationException
     *             Thrown when CertificateRequest generation or export is failed.
     * @throws CertificateServiceException
     *             is thrown when internal db error occurs while fetching CSR.
     * @throws InvalidOperationException
     *             Thrown when the certificateGenerationInfo is not found.
     */
    PKCS10CertificationRequestHolder getCSR(final String caName) throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidOperationException;

    /**
     * This method is used for handling the import certificate request for the certificate signed by external root ca
     * 
     * @param caName
     *            name of the CA entity for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @param enableRFCValidation
     *            flag to enable RFC validations on the provided certificate
     * @param caReIssueType
     *            type that specifies re issue need to be done for Sub CAs of Root CA
     * @throws AlgorithmNotFoundException
     *             This exception is thrown if the given algorithm is not supported/not present in the database ,in case of CertificateImport/ CertificateGeneration for Re-issue of child CA's of
     *             imported CA
     * @throws CANotFoundException
     *             This exception is thrown if the given CA is not present in the database
     * @throws CertificateGenerationException
     *             This exception is thrown to indicate that an exception has occurred during certificate generation during Re-issue of child CA's of imported CA
     * @throws CertificateNotFoundException
     *             This exception is thrown when CA does not have Active Certificate to revoke during Re-issue of child CA's of imported CA
     * @throws CertificateServiceException
     *             This exception is thrown to indicate any internal database errors or any unconditional exceptions during Root CA certificate import signed by external CA and also during Re-issue of
     *             child CA's of imported CA
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain is expired.
     * @throws InvalidCAException
     *             This exception is thrown when the given CA is not having a valid state during certificate import
     * @throws IssuerCertificateRevokedException
     *             This exception is thrown if the Issuer certificate is already revoked during Re-issue of child CA's of imported CA
     * @throws InvalidEntityException
     *             This exception is thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             This exception is thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             This exception is thrown when the revocation invalidityDate is beyond the certificate validity.
     * @throws InvalidOperationException
     *             This exception is thrown when the given CA is not root CA.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     */
    void importCertificate(final String caName, final X509Certificate x509Certificate, final boolean enableRFCValidation, final CAReIssueType caReIssueType) throws AlgorithmNotFoundException,
            CANotFoundException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException,
            IssuerCertificateRevokedException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException, RevokedCertificateException,
            RootCertificateRevocationException, RevocationServiceException;

    /**
     * This method is used for handling the force import certificate request for the certificate signed by external root ca
     * 
     * @param caName
     *            name of the CA entity for which certificate needs to be imported.
     * @param x509Certificate
     *            X509Certificate object containing certificate data.
     * @param enableRFCValidation
     *            flag to enable RFC validations on the provided certificate
     * @param caReIssueType
     *            type that specifies re issue need to be done for Sub CAs of Root CA
     * @throws AlgorithmNotFoundException
     *             This exception is thrown if the given algorithm is not supported/not present in the database ,in case of CertificateImport/ CertificateGeneration for Re-issue of child CA's of
     *             imported CA
     * @throws CANotFoundException
     *             This exception is thrown if the given CA is not present in the database
     * @throws CertificateGenerationException
     *             This exception is thrown to indicate that an exception has occurred during certificate generation during Re-issue of child CA's of imported CA
     * @throws CertificateNotFoundException
     *             This exception is thrown when CA does not have Active Certificate to revoke during Re-issue of child CA's of imported CA
     * @throws CertificateServiceException
     *             This exception is thrown to indicate any internal database errors or any unconditional exceptions during Root CA certificate import signed by external CA and also during Re-issue of
     *             child CA's of imported CA
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain is expired.
     * @throws InvalidCAException
     *             This exception is thrown when the given CA is not having a valid state during certificate import
     * @throws IssuerCertificateRevokedException
     *             This exception is thrown if the Issuer certificate is already revoked during Re-issue of child CA's of imported CA
     * @throws InvalidEntityException
     *             This exception is thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             This exception is thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             This exception is thrown when the revocation invalidityDate is beyond the certificate validity.
     * @throws InvalidOperationException
     *             This exception is thrown when the given CA is not root CA.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     * @throws RevocationServiceException
     *             Thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             Thrown if Root CA certificate need to be revoked.
     */
    void forceImportCertificate(final String caName, final X509Certificate x509Certificate, final boolean enableRFCValidation, final CAReIssueType caReIssueType) throws AlgorithmNotFoundException,
            CANotFoundException, CertificateGenerationException, CertificateNotFoundException, CertificateServiceException, ExpiredCertificateException, InvalidCAException,
            IssuerCertificateRevokedException, InvalidEntityException, InvalidEntityAttributeException, InvalidInvalidityDateException, InvalidOperationException, RevokedCertificateException,
            RevocationServiceException, RootCertificateRevocationException;

    /**
     * This API method will publish the certificate for a given entity name to Trust distribution service based on CA Name and certificateStatus.
     * 
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     * 
     * @throws CANotFoundException
     *             This exception is thrown if the given CA is not present in the database
     * @throws CertificateServiceException
     *             Thrown in case there are any internal errors while fetching entity/certificate or dispatching event. All internal exceptions are wrapped to this high level exception.
     */
    void publishCertificate(final String entityName) throws CANotFoundException, CertificateServiceException;

    /**
     * This API method will un-publish the certificate for a given entity Name to Trust distribution point service.
     * 
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     * 
     * @throws CANotFoundException
     *             Thrown in case entity is not found with the given name
     * @throws CertificateServiceException
     *             Thrown in case there are any internal errors while fetching entity/certificate or dispatching event. All internal exceptions are wrapped to this high level exception.
     */
    void unPublishCertificate(final String entityName) throws CANotFoundException, CertificateServiceException;

    // TODO:TORF-85220 for List certificates for WEbcli command
    /**
     * Returns list of certificateChains {@link CertificateChain} of active and/or inactive certificates of CAEntity based on certificateStatus. Returns list of certificateChains
     * {@link CertificateChain} of both active and inactive certificates of CAEntity if certificateStatus is null or empty.
     * 
     * @param entityName
     *            name of the Entity.
     * @param certificateStatus
     *            certificateStatus {@link CertificateStatus} contains Active or InActive or both.
     * @return certificateChains list of complete chain of certificates from CAEntity to RootCA.
     * 
     * @throws CertificateServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidCertificateStatusException
     *             Thrown when the Certificate Status is invalid to get the CertificateChain.
     * @throws InvalidEntityException
     *             Thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     */
    List<CertificateChain> getCertificateChainList(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException, InvalidCAException,
            InvalidCertificateStatusException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * Returns list of entities certificates {@link CertificateInfo} issued for a given caEntityName, Serial Number and entity certificate status.
     * 
     * @param caCertificateIdentifier
     *            is the CA certificate information holder containing CA name and Certificate serial number.
     * 
     * @param status
     *            Fetch the entity certificates which matches the list of {@link CertificateStatus} values
     * 
     * @return list of {@link CertificateInfo} objects
     * 
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given caentity name with corresponding Entity certificate Status.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws MissingMandatoryFieldException
     *             Throws in case the caName is null or empty, or the cerficateSerialNumber is empty or null.
     */
    List<CertificateInfo> listIssuedCertificates(final CACertificateIdentifier caCertificateIdentifier, final CertificateStatus... status) throws CANotFoundException, CertificateNotFoundException,
            CertificateServiceException, MissingMandatoryFieldException;

    /**
     * Returns list of entities certificates {@link CertificateInfo} issued identified by particular {@link DNBasedCertificateIdentifier} and entity certificate status.
     * 
     * @param dnBasedCertIdentifier
     *            contains subjectDn,issuerDn and serialNumber .
     * @param status
     *            Fetch the entity certificates which matches the list of {@link CertificateStatus} values
     * 
     * @return list of {@link CertificateInfo} objects
     *
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given caentity name with corresponding Entity certificate Status.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws MissingMandatoryFieldException
     *             Throws in case the subjectDN or issuerDN or cerficateSerialNumber is null or empty.
     */
    List<CertificateInfo> listIssuedCertificates(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier, final CertificateStatus... status) throws CANotFoundException,
            CertificateNotFoundException, CertificateServiceException, MissingMandatoryFieldException;

    /**
     * Returns list of certificates {@link Certificate} as chain for both active and inactive certificates of CAEntity.
     * 
     * @param entityName
     *            name of the Entity.
     * @return list of certificates from CAEntity to RootCA.
     * 
     * @throws CertificateServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws InvalidCAException
     *             Thrown in case the given CAEntity is not found or doesn't have any valid certificate or doesn't have a valid issuer.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     */
    List<Certificate> getCertificateChain(final String entityName) throws CertificateServiceException, InvalidCAException, InvalidEntityAttributeException;

}
