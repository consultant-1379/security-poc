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
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.api;

import java.util.List;
import java.util.Map;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.RevocationServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateNotFoundException;

/**
 *
 * This Interface provides CRL Management Service from PKI Core. The methods include generateCRL,getLatestCRLs and getAllCRLs for CAEntity.
 *
 * @author xramdag
 * @since 23/09/2015
 */
@EService
@Remote
public interface CRLManagementService {

    /**
     * This method is used to generateCRL for a given CA and Certificate serial number.
     *
     * @param caCertIdentifier
     *            CRLInfo is generated using Certificate identified by {@link CACertificateIdentifier} object.
     * @return CRLInfo object generated
     * @throws CertificateExpiredException
     *             thrown when the CRL request is received for an expired certificate.
     * @throws CertificateNotFoundException
     *             in case the CA Certificate to issue CRL is not found.
     * @throws CertificateRevokedException
     *             thrown when the CRL request is received for a revoked certificate.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CRLGenerationException
     *             Thrown when internal error occurs during CRL generation.
     * @throws CRLServiceException
     *             in case of any database failures or internal errors.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the entity.
     * @throws InvalidCRLExtensionException
     *             in case of CRL extensions passed in are not valid.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors in case of Revocation.
     */
    CRLInfo generateCRL(final CACertificateIdentifier caCertIdentifier) throws CertificateExpiredException, CertificateRevokedException, CertificateNotFoundException, CoreEntityNotFoundException,
            CRLServiceException, CRLGenerationException, InvalidCoreEntityAttributeException, RevocationServiceException;

    /**
     * This method is used to get Latest CRLInfos of corresponding CAs.
     *
     * @param caCertIdentifierList
     *            contains list of {@link CACertificateIdentifier} objects using which CRLInfo is retrieved.
     * @return HashMap object which contains caCertificateIdentifier and corresponding CRLInfos.
     * 
     * @throws CRLServiceException
     *             in case of any database failures or internal errors.
     *
     */
    Map<CACertificateIdentifier, CRLInfo> getLatestCRLs(List<CACertificateIdentifier> caCertIdentifierList) throws CRLServiceException;

    /**
     * This method is used to get AllCRLs identified by CA Name and its Certificate Serial Number.
     *
     * @param caCertIdentifier
     *            CRLInfo is retrieved using Certificate identified by {@link CACertificateIdentifier} object passed.
     *
     * @return list of CRLInfo objects or null if crl not found
     *
     * @throws CertificateNotFoundException
     *             in case certificate does not exist.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws CRLServiceException
     *             in case of any database failures or internal errors.
     * @throws InvalidCAException
     *             thrown when the given CAEntity is not valid.
     */
    List<CRLInfo> getAllCRLs(final CACertificateIdentifier caCertIdentifier) throws CertificateNotFoundException, CoreEntityNotFoundException, CRLServiceException, InvalidCAException;

    /**
     * This method is used to get all CRLs which are issued by the certificate with given status and this certificate belongs to the given CA Entity.
     *
     * @param caEntityName
     *            is the name of the caEntity.
     * @param certificateStatus
     *            is the status of the Certificate which is used to identify the Certificate.
     * @return Map object which contains {@link CACertificateIdentifier} object as key and list of all {@link CRLInfo} objects as value. The caCertificateIdentifier object gives the certificate
     *         information of the given CAName and this certificate information is related to the issuer certificate of CRL.
     *
     * @throws CertificateNotFoundException
     *             thrown when no certificate exists with the given certificate status.
     * @throws CoreEntityNotFoundException
     *             thrown when given CA for which the CRL has to be fetched does not exists.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during CRL fetching.
     * @throws InvalidCAException
     *             thrown when the given CAEntity is not valid.
     *
     *
     */
    Map<CACertificateIdentifier, List<CRLInfo>> getAllCRLs(final String caEntityName, final CertificateStatus certificateStatus) throws CertificateNotFoundException, CoreEntityNotFoundException,
            CRLServiceException, InvalidCAException;

    /**
     * getCRL will get the CRL with the given CRLNumber and which is issued by the given CA
     *
     * @param caEntityName
     *            is the name of CAEntity.
     * @param cRLNumber
     *            is the CRLNumber which is assigned to the CRL to identify CRL
     * @return CRLInfo object which contains the attributes like thisUpdate, nextUpdate,CRLNumber,CRLStatus.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CRLNotFoundException
     *             thrown when CRL for the requested CA does not exist.
     * @throws CRLServiceException
     *             thrown when there is any internal error like database error during the fetching the CRL.
     * @throws InvalidCAException
     *             thrown when the given CAEntity is not valid.
     *
     *
     */
    CRLInfo getCRL(final String caEntityName, final CRLNumber cRLNumber) throws CoreEntityNotFoundException, CRLNotFoundException, CRLServiceException, InvalidCAException;

    /**
     * This method will update CRL status to EXPIRED whose validity expired.
     *
     * @throws CRLServiceException
     *             Thrown, if any database failures occurs.
     */
    void updateCRLStatusToExpired() throws CRLServiceException;

    /**
     * This method will update CRL status to INVALID whose issuer certificate has revoked.
     *
     * @throws CRLServiceException
     *             Thrown, if any database failures occurs.
     */
    void updateCRLStatusToInvalid() throws CRLServiceException;
}
