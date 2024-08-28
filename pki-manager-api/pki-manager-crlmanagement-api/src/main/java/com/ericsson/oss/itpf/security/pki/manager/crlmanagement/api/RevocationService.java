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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api;

import java.util.Date;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;

/**
 * This is an interface for RevocationService. It provides below Revocation operations.
 * <ul>
 * <li>Revoke all the Certificates of given CA/End Entity</li>
 * <li>Revoke a particular Certificate</li>
 * </ul>
 * 
 * @author xvambur
 */
@EService
@Remote
public interface RevocationService {

    /**
     * This API method is used to revoke all the valid Certificates of the given Entity.
     * 
     * @param entityName
     *            is the name of the Entity.
     * @param reason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the date on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown if expired certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown when the given invalidityDate is beyond the certificate validity.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown if revoked certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    void revokeEntityCertificates(final String entityName, final RevocationReason reason, final Date invalidityDate) throws CertificateNotFoundException, EntityAlreadyExistsException,
            EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevocationServiceException,
            RevokedCertificateException, RootCertificateRevocationException;

    /**
     * This API method is used to revoke all the valid Certificates of the given CA Entity.
     * 
     * @param entityName
     *            is the name of the CAEntity.
     * @param reason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the date on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the CAEntity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown if expired certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown when the given invalidityDate is beyond the certificate validity.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevokedCertificateException
     *             thrown if revoked certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    void revokeCAEntityCertificates(final String entityName, final RevocationReason reason, final Date invalidityDate) throws CertificateNotFoundException, EntityAlreadyExistsException,
            EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException,
            RevocationServiceException, RootCertificateRevocationException;

    /**
     * This API method is used to revoke particular Certificate of an CAEntity or Entity. The details of the Certificate is given in the CertificateIdentifier.
     * 
     * @param certificateIdentifier
     *            is the object of CertificateIdentifier, has the fields issuerName and serialNumber.
     * @param reason
     *            is the RevocationReason enum which has the reason values defined by RFC5280.
     * @param invalidityDate
     *            is the optional value and it is the on which it is known or suspected that the private key was compromised or that the Certificate otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when the given certificate id of the CAEntity or Entity is not present.
     * @throws EntityAlreadyExistsException
     *             thrown when the name of the entity already exists in DB while updating entity status.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown if expired certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown when the given invalidityDate is beyond the certificate validity.
     * @throws IssuerNotFoundException
     *             thrown when issuer is not found.
     * @throws RevokedCertificateException
     *             thrown if revoked certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    void revokeCertificateByIssuerName(final CertificateIdentifier certificateIdentifier, final RevocationReason reason, final Date invalidityDate) throws CertificateNotFoundException,
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerNotFoundException,
            RevokedCertificateException, RevocationServiceException, RootCertificateRevocationException;

    /**
     * revokeCertificateByDN will revoke the particular certificate which is identified by particular @link DNBasedCertificateIdentifier.
     * 
     * @param dnBasedCertIdentifier
     *            contains subjectDn,issuerDn and serialNumber of the certificate to be revoked.
     * @param reason
     *            reason for revoking the certificate.
     * @param invalidityDate
     *            provides the date on which it is known or suspected that the private key was compromised or that the certificate otherwise became invalid.
     * @throws CertificateNotFoundException
     *             thrown when certificate is not present.
     * @throws EntityNotFoundException
     *             thrown when given Entity doesn't exists.
     * @throws ExpiredCertificateException
     *             thrown if expired certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown when the given revocation invalidity date is beyond the certificate validity.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevokedCertificateException
     *             thrown if revoked certificate found in the chain of the certificate for which the revocation request is raised.
     * @throws RevocationServiceException
     *             thrown to indicate any internal database errors or any unconditional exceptions occurs during the revocation of a Certificate.
     * @throws RootCertificateRevocationException
     *             thrown to indicate Root CA cannot be revoked.
     * 
     */
    void revokeCertificateByDN(final DNBasedCertificateIdentifier dnBasedCertIdentifier, final RevocationReason reason, final Date invalidityDate) throws CertificateNotFoundException,
            EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException, RevokedCertificateException,
            RevocationServiceException, RootCertificateRevocationException;

}
