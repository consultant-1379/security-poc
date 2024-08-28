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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.impl;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators.CAValidator;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

public class CAEntityManager {

    @Inject
    Logger logger;

    @Inject
    CAEntityPersistenceHandler cAEntityPersistenceHandler;

    @Inject
    CAValidator cAValidator;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateAuthorityModelMapper cAEntityMapper;

    @Inject
    private SystemRecorder systemRecorder;

    private final static String NAME_PATH = "name";

    /**
     * Validates {@link CertificateAuthority} object and creates it in the database.
     * 
     * @param certificateAuthority
     *            {@link CertificateAuthority} object to be validated and stored in database.
     * @return CertificateAuthority
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case {@link CertificateAuthority} object already exists in database.
     * @throws CoreEntityNotFoundException
     *             Thrown when entity not found in the system.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidCoreEntityAttributeException
     *             thrown when an invalid attribute is present in the entity.
     */
    public CertificateAuthority createCA(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException {

        logger.debug("creating Certificate Authroity {}", certificateAuthority);

        final CertificateAuthority certAuthority = validateAndCreate(certificateAuthority);

        logger.debug(" Certificate Authroity Created {}", certAuthority);

        systemRecorder.recordSecurityEvent("PKICore.EntityManagement", "CAEntityManager", "Created CA entity for " + certificateAuthority.getName(),
                "PKICORE.CREATE_CA", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return certAuthority;
    }

    private CertificateAuthority validateAndCreate(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityServiceException,
            InvalidCoreEntityAttributeException {

        cAValidator.validateCreate(certificateAuthority);

        cAEntityPersistenceHandler.persistCA(certificateAuthority);

        CertificateAuthorityData certAuthorityData = null;
        try {
            certAuthorityData = persistenceManager.findEntityByName(CertificateAuthorityData.class, certificateAuthority.getName(), NAME_PATH);
        } catch (PersistenceException persistenceexception) {
            logger.error("Transaction Inactive Error in retreive entityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }

        CertificateAuthority certAuthority = null;
        try {
            certAuthority = cAEntityMapper.toAPIModel(certAuthorityData);
        } catch (CRLServiceException | InvalidCRLGenerationInfoException | InvalidCertificateException e) {
            throw new InvalidCoreEntityAttributeException(e);
        }

        return certAuthority;
    }

    /**
     * Validates {@link CertificateAuthority} object and updates it in the database.
     * 
     * @param certificateAuthority
     *            {@link CertificateAuthority} object to be updated in database.
     * @return CertificateAuthority
     * @throws CoreEntityAlreadyExistsException
     *             thrown when CA with same name exists in the db.
     * @throws CoreEntityNotFoundException
     *             Thrown in case {@link CertificateAuthority} object not found in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws InvalidCoreEntityAttributeException
     *             thrown when an invalid attribute is present in the entity.
     */
    public CertificateAuthority updateCA(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException,
            InvalidCoreEntityAttributeException {

        logger.debug("updating Certificate Authroity {}", certificateAuthority);

        final CertificateAuthority certAuthority = validateAndUpdate(certificateAuthority);

        logger.debug("Certificate Authroity Updated {}", certAuthority);

        return certAuthority;
    }

    private CertificateAuthority validateAndUpdate(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException,
            InvalidCoreEntityAttributeException {
        CertificateAuthorityData certAuthorityData = null;
        cAValidator.validateUpdate(certificateAuthority);

        cAEntityPersistenceHandler.updateCA(certificateAuthority);

        try {
            certAuthorityData = persistenceManager.findEntityByName(CertificateAuthorityData.class, certificateAuthority.getName(), NAME_PATH);

        } catch (PersistenceException persistenceException) {
            logger.debug("Error while checking database if name {} exists.", certificateAuthority.getName());
            throw new CoreEntityServiceException("Error while checking database if name " + certificateAuthority.getName() + " exists ", persistenceException);
        }
        cAEntityPersistenceHandler.updateCertificateStatus(certAuthorityData, certificateAuthority.getStatus());

        CertificateAuthority certAuthority = null;
        try {
            certAuthority = cAEntityMapper.toAPIModel(certAuthorityData);
        } catch (CRLServiceException | InvalidCRLGenerationInfoException | InvalidCertificateException e) {
            throw new InvalidCoreEntityAttributeException(e);
        }

        return certAuthority;
    }

    /**
     * Validates {@link CertificateAuthority} object and Deletes it in the database.
     * 
     * @param certificateAuthority
     *            {@link CertificateAuthority} object to be updated in database.
     * @throws CoreEntityNotFoundException
     *             Thrown in case {@link CertificateAuthority} object not found in the database.
     * @throws CoreEntityServiceException
     *             Thrown when any internal error occurs in system.
     * @throws CoreEntityInUseException
     *             Thrown when the CA has Active Certificates
     */
    public void deleteCA(final CertificateAuthority certificateAuthority) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException {

        logger.debug("deleting Certificate Authroity {}", certificateAuthority);

        validateAndDelete(certificateAuthority);

        logger.debug("Certificate Authroity Deleted {}" , certificateAuthority);

        systemRecorder.recordSecurityEvent("PKICore.EntityManagement", "CAEntityManager", "Deleted CA entity " + certificateAuthority.getName(),
                "PKICORE.DELETE_CA", ErrorSeverity.INFORMATIONAL, "SUCCESS");
    }

    private void validateAndDelete(final CertificateAuthority certificateAuthority) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException {

        if (certificateAuthority.getName() != null) {
            final String trimmedCAEntityName = certificateAuthority.getName().trim();
            certificateAuthority.setName(trimmedCAEntityName);

            cAValidator.checkEntityNameFormat(certificateAuthority.getName());
        }

        final CertificateAuthorityData certificateAuthorityData = cAEntityPersistenceHandler.getCAData(certificateAuthority);
        final CAStatus caStatus = certificateAuthorityData.getStatus();
        final String caEntityName = certificateAuthorityData.getName();

        if (cAValidator.isCACanBeDeleted(caStatus)) {
            if (caStatus == CAStatus.NEW) {
                cAEntityPersistenceHandler.deleteCA(certificateAuthorityData);
            } else if (caStatus == CAStatus.INACTIVE) {
                cAValidator.checkCAEntityHasEntities(caEntityName);
                cAEntityPersistenceHandler.updateCAStatus(certificateAuthorityData, CAStatus.DELETED);
            }
        }
    }
}
