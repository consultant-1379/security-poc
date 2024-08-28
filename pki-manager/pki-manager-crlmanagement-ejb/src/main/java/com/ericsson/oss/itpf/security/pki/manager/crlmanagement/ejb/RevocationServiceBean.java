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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import java.util.Date;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.RevocationService;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.RevocationManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;

/**
 * This class implements {@link RevocationService}
 *
 */
@Stateless
@EServiceQualifier("1.0.0")
@ErrorLogAnnotation()
public class RevocationServiceBean implements RevocationService {

    @Inject
    Logger logger;

    @Inject
    RevocationManager revocationManager;

    /**
     * This method is used to revoke all the valid Certificates of the given CA Entity.
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
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attriubte.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.REVOCATIONMGMT, metricType = MetricType.REVOKE)
    public void revokeCAEntityCertificates(final String entityName, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException,
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException,
            RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {
        logger.debug("Revoke CAEntity Certificate");

        revocationManager.revokeCAEntityCertificates(entityName, revocationReason, invalidityDate);
    }

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
     *             thrown when the given certificate id of the CAEntity or Entity is not present.
     * @throws EntityNotFoundException
     *             thrown when the requested Certificate's entity is not present.
     * @throws ExpiredCertificateException
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.REVOCATIONMGMT, metricType = MetricType.REVOKE)
    public void revokeCertificateByDN(final DNBasedCertificateIdentifier dnBasedCertificateIdentifier, final RevocationReason revocationReason, final Date invalidityDate)
            throws CertificateNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException,
            IssuerCertificateRevokedException, RevokedCertificateException, RootCertificateRevocationException, RevocationServiceException {

        logger.debug("Revoke Certificate with DNBasedCertificateIdentifier");

        revocationManager.revokeCertificateByDN(dnBasedCertificateIdentifier, revocationReason, invalidityDate);
    }

    /**
     * This method is used to revoke particular Certificate of an CAEntity or Entity. The details of the Certificate is given in the CertificateIdentifier.
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
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the Issuer Certificate of the given CAEntity or Entity Certificate is already revoked.
     * @throws IssuerNotFoundException
     *             thrown when issuer is not found.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.REVOCATIONMGMT, metricType = MetricType.REVOKE)
    public void revokeCertificateByIssuerName(final CertificateIdentifier certificateIdentifier, final RevocationReason revocationReason, final Date invalidityDate)
            throws CertificateNotFoundException, EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException,
            IssuerCertificateRevokedException, IssuerNotFoundException, RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {

        logger.debug("Revoke Certificate with CertificateIdentifer");

        revocationManager.revokeCertificateByIssuerName(certificateIdentifier, revocationReason, invalidityDate);

    }

    /**
     * This method is used to revoke all the valid Certificates of the given Entity.
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
     *             thrown when the revocation request is raised for an expired certificate.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidInvalidityDateException
     *             thrown while validating the InvalidityDate during Revocation.
     * @throws IssuerCertificateRevokedException
     *             thrown when the issuer certificate in the certificate-chain is revoked.
     * @throws RevocationServiceException
     *             thrown when there is any internal error like any internal database failures during the revocation.
     * @throws RevokedCertificateException
     *             thrown when the revocation request is raised for a revoked certificate.
     * @throws RootCertificateRevocationException
     *             thrown when Revocation Request is for the Root CA to indicate that Root CA cannot be revoked.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.REVOCATIONMGMT, metricType = MetricType.REVOKE)
    public void revokeEntityCertificates(final String entityName, final RevocationReason revocationReason, final Date invalidityDate) throws CertificateNotFoundException,
            EntityAlreadyExistsException, EntityNotFoundException, ExpiredCertificateException, InvalidEntityAttributeException, InvalidInvalidityDateException, IssuerCertificateRevokedException,
            RevocationServiceException, RevokedCertificateException, RootCertificateRevocationException {
        logger.debug("Revoke Entity Certificates");

        revocationManager.revokeEntityCertificates(entityName, revocationReason, invalidityDate);
    }
}
