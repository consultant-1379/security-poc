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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.validator;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.RevokedCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

public class CertificateValidator {

    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    /**
     * Validates issuer certificates to check it has ACTIVE certificate and has valid certificate chain.
     *
     * @param issuerName
     *            name of issuer
     * @throws ExpiredCertificateException
     *             Thrown when the certificate in the chain gets expired.
     * @throws InvalidCAException
     *             Thrown in case of CAEntity does not have an ACTIVE certificate.
     * @throws RevokedCertificateException
     *             Thrown when the certificate in the chain gets revoked.
     */
    // TODO : This validation need to be moved to validation Service, user story ref : TORF-110470
    public void validateIssuerChain(final String issuerName) throws ExpiredCertificateException, InvalidCAException, RevokedCertificateException,PersistenceException {

        final List<CertificateData> certificateDatas = caPersistenceHelper.getCertificateDatas(issuerName, CertificateStatus.ACTIVE);

        if (certificateDatas == null || certificateDatas.isEmpty()) {
            logger.error("Could not issue certificate because CAEntity {} does not have an ACTIVE certificate", issuerName);
            throw new InvalidCAException("Could not issue certificate because CAEntity " + issuerName + " does not have an ACTIVE certificate");
        }
        certificatePersistenceHelper.validateCertificateChain(certificateDatas.get(0), EnumSet.of(CertificateStatus.REVOKED, CertificateStatus.EXPIRED));
    }

    /**
     * Check for Valid entity statuses applicable for reissue operation.
     *
     * @param entity
     *            entity {@link AbstractEntity}
     * @throws InvalidCAException
     *             Thrown in case of CAEntity is in New state.
     * @throws InvalidEntityException
     *             Thrown in case of Entity is in New state.
     */
    public void verifyEntityStatusForReissue(final AbstractEntity entity) throws InvalidCAException, InvalidEntityException {

        if (entity.getType() == EntityType.CA_ENTITY) {
            final CAEntity caEntity = (CAEntity) entity;
            final String caEntityCertificateAutorityName = caEntity.getCertificateAuthority().getName();
            final String caEntityCertificateAuthorityStatus = caEntity.getCertificateAuthority().getStatus().value();
            if (caEntity.getCertificateAuthority().getStatus() == CAStatus.NEW) {

                logger.error("Could not reissue certificate because CAEntity {} is in {} state", caEntityCertificateAutorityName, caEntityCertificateAuthorityStatus);
                throw new InvalidCAException("Could not reissue certificate because CAEntity " + caEntityCertificateAutorityName + " is in "
                        + caEntityCertificateAuthorityStatus + " state ");
            }

        } else {

            final Entity endEntity = (Entity) entity;
            final String endEntityInfoName = endEntity.getEntityInfo().getName();
            final String endEntityInfoStatus = endEntity.getEntityInfo().getStatus().value();
            if (endEntity.getEntityInfo().getStatus() == EntityStatus.NEW) {
                logger.error("Could not reissue certificate because Entity {} is in {} state", endEntityInfoName, endEntityInfoStatus);
                throw new InvalidEntityException("Could not reissue certificate because Entity " + endEntityInfoName + " is in " + endEntityInfoStatus
                        + " state ");
            }

        }

    }

    /**
     * Validates DNBasedCertificateIdentifier input for list Issued certificates
     *
     * @param dNBasedCertificateIdentifier
     *            contains subjectDn,issuerDn and serialNumber
     * @throws MissingMandatoryFieldException
     *             is thrown if the invalid attribute in the {@link DNBasedCertificateIdentifier}.
     */
    public void validateDNBasedCertificateIdentifier(final DNBasedCertificateIdentifier dNBasedCertificateIdentifier) throws MissingMandatoryFieldException {

        if (dNBasedCertificateIdentifier.getSubjectDN() == null && dNBasedCertificateIdentifier.getIssuerDN() == null && dNBasedCertificateIdentifier.getCerficateSerialNumber() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.SUBJECTDN_ISSUERDN_SERIALNUMBER_MANDATORY);
        }

        if (dNBasedCertificateIdentifier.getIssuerDN() != null && dNBasedCertificateIdentifier.getSubjectDN() == null && dNBasedCertificateIdentifier.getCerficateSerialNumber() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.SUBJECTDN_SERIALNUMBER_MANDATORY);
        }
    }

    /**
     * Validates DNBasedCertificateIdentifier input and caEntityDatasCount by dNBasedIdentifier
     *
     * @param dNBasedCertificateIdentifier
     *            contains subjectDn,issuerDn and serialNumber
     * @param caEntitiesCount
     *            caEntityDatasCount by dNBasedIdentifier
     *
     * @throws MissingMandatoryFieldException
     *             Invalid input
     */
    public void validateDNBasedCertificateIdentifier(final DNBasedCertificateIdentifier dNBasedIdentifier, final Long caEntitiesCount) throws MissingMandatoryFieldException {

        if (caEntitiesCount == 0) {
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND_SUBJECTDN);
        }
        if (caEntitiesCount > 1 && dNBasedIdentifier.getSubjectDN() != null && dNBasedIdentifier.getIssuerDN() == null && dNBasedIdentifier.getCerficateSerialNumber() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.ISSUERDN_SERIALNUMBER_MANDATORY);
        }
        if (caEntitiesCount > 1 && dNBasedIdentifier.getSubjectDN() != null && dNBasedIdentifier.getIssuerDN() != null && dNBasedIdentifier.getCerficateSerialNumber() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.ISSUERDN_SERIALNUMBER_MANDATORY);
        }
        if (caEntitiesCount > 1 && dNBasedIdentifier.getSubjectDN() != null && dNBasedIdentifier.getCerficateSerialNumber() != null && dNBasedIdentifier.getIssuerDN() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.ISSUERDN_SERIALNUMBER_MANDATORY);
        }
        if (caEntitiesCount > 1 && dNBasedIdentifier.getCerficateSerialNumber() != null && dNBasedIdentifier.getIssuerDN() != null && dNBasedIdentifier.getSubjectDN() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.SUBJECTDN_MANDATORY);
        }
    }

    /**
     * Validates CACertificateIdentifier and certificate status input for list Issued certificates
     *
     * @param cACertificateIdentifier
     *            contains cAName and serialNumber
     *
     * @throws MissingMandatoryFieldException
     *             is thrown if the invalid attribute in the {@link CACertificateIdentifier}.
     */
    public void validateCACertificateIdentifier(final CACertificateIdentifier cACertificateIdentifier, final CertificateStatus... certificateStatus) throws MissingMandatoryFieldException {

        if (certificateStatus == null || certificateStatus.length == 0) {
            throw new MissingMandatoryFieldException(ErrorMessages.CERTIFICATE_STATUS_MANDATORY);
        }
        if (cACertificateIdentifier.getCaName() == null && cACertificateIdentifier.getCerficateSerialNumber() == null) {
            throw new MissingMandatoryFieldException(ErrorMessages.CANAME_SERIALNUMBER_MANDATORY);
        }
    }

    /**
     * Validates CACertificateIdentifier input and certificateDatasCount by cACertificateIdentifier
     *
     * @param cACertificateIdentifier
     *            contains cAName and serialNumber
     * @param certificateDatasCount
     *            certificateDatasCount by cACertificateIdentifier
     *
     * @throws CertificateNotFoundException
     *             Invalid input
     */
    public void validateCACertificateIdentifier(final CACertificateIdentifier cACertificateIdentifier, final Integer certificateDatasCount) throws CertificateNotFoundException {

        if (certificateDatasCount == 0) {
            throw new CertificateNotFoundException(ErrorMessages.CA_CERTIFICATE_NOT_FOUND);
        }
        if (certificateDatasCount > 1 && cACertificateIdentifier.getCerficateSerialNumber() == null) {
            throw new CertificateNotFoundException(ErrorMessages.SERIALNUMBER_MANDATORY_LIST_ISSUED_CERTIFICATES);
        }
    }

    /**
     * Check for Valid certificate statuses applicable for CA Entity Certificate Renew operation.
     * 
     * @param caEntity
     *            {@link CAEntity}
     * @throws InvalidCAException
     *             Thrown in case of CAEntity is in New state.
     * @throws IOException
     * @throws PersistenceException
     * @throws CertificateException
     */
    public void verifyCAActiveCertificatesForRenew(final CAEntity caEntity) throws InvalidCAException, CertificateException, PersistenceException, IOException {

        if (caEntity.getCertificateAuthority() != null) {

            final X509Certificate x509Certificate = caPersistenceHelper.getActiveCertificate(caEntity.getCertificateAuthority().getName());

            if (x509Certificate == null) {

                logger.error("Renew operation is not allowed for the CAEntity {} as the CAENTITY Certificate is not ACTIVE ", caEntity.getCertificateAuthority().getName());
                throw new InvalidCAException("Could not Renew certificate because " + ErrorMessages.CA_ACTIVE_CERTIFICATE_NOT_FOUND + ", Perform Rekey operation ");

            }
        }

    }
}
