/*------------------------------------------------------------------------------
 ********************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *********************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import java.util.*;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.ExternalCAManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExtCAMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ExtCAManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;

/**
 * This class implements {@link ExtCAManagementService}
 *
 */
@Profiled
@Stateless
@EServiceQualifier("1.0.0")
public class ExtCAManagementServiceBean implements ExtCAManagementService {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    private EntitiesManager entitiesManager;

    @Inject
    private Logger logger;

    @Inject
    private ExtCAMapper extCaMapper;

    @Inject
    private ExternalCAManagementAuthorizationManager externalCAManagementAuthorizationManager;

    /**
     * Get an ExtCA based on ExtCA Id/name.
     *
     * @param extCA
     *            Object of ExtCA with id/name set.
     * @return Returns object of ExtCA.
     * @throws ExternalCredentialMgmtServiceException
     *             v when any internal Database errors or service exception occur.
     * @throws ExternalCANotFoundException
     *             Thrown when no extCA exists with given id/name.
     * @throws ExternalCRLEncodedException
     *             Thrown when the CRL is not correct.
     */
    @Override
    public ExtCA getExtCA(final ExtCA extCA) throws ExternalCANotFoundException,ExternalCRLEncodedException, ExternalCredentialMgmtServiceException {
        logger.debug("Retrieving external CA {}", extCA);
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.READ);
        CAEntityData caEntityActual = null;
        try {
            caEntityActual = persistenceManager.findEntityByName(CAEntityData.class, extCA.getCertificateAuthority().getName(), "certificateAuthorityData.name");
        } catch (final PersistenceException e) {
            logger.debug("Error occured while retrieving external CA data from database based on id/name ", e);
            throw new ExternalCredentialMgmtServiceException();
        }
        if (caEntityActual == null) {
            throw new ExternalCANotFoundException(ErrorMessages.EXTERNAL_CA_NOT_FOUND);
        } else if (!caEntityActual.isExternalCA()) {
            throw new ExternalCANotFoundException(ErrorMessages.CA_ISNT_EXTERNAL_CA);
        }

        final ExtCA extCAActual = (ExtCA) extCaMapper.toAPIFromModel(caEntityActual);
        return extCAActual;
    }

    /**
     * Get all extCAs .
     *
     * @return List of ExtCA objects.
     *
     * @throws ExternalCRLEncodedException
     *             Thrown when the CRL is not correct.
     * @throws ExternalCredentialMgmtServiceException
     *             Thrown when any internal Database errors or service exception occur.
     */
    @Override
    public List<ExtCA> getExtCAs() throws ExternalCRLEncodedException,ExternalCredentialMgmtServiceException {
        logger.debug("Retrieving external CAs ");
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.READ);
        final List<ExtCA> extCas = new ArrayList<ExtCA>();
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("externalCA", true);
        List<CAEntityData> retievedExtCAs = null;
        try {
            retievedExtCAs = persistenceManager.findEntitiesWhere(CAEntityData.class, input);
        } catch (final PersistenceException e) {
            logger.debug("Error occured while retrieving external CA data from database using the entities ", e);
            throw new ExternalCredentialMgmtServiceException();
        }
        if (retievedExtCAs != null) {
            for (final CAEntityData retievedExtCA : retievedExtCAs) {
                if (retievedExtCA.getCertificateAuthorityData().getCertificateDatas().size() > 0) {
                    final ExtCA extCAActual = (ExtCA) extCaMapper.toAPIFromModel(retievedExtCA);
                    extCas.add(extCAActual);
                }
            }
        }
        return extCas;
    }

    /**
     * Get ExtCA by subject specified.
     *
     * @param subject
     *            Object of subject class with fields set.
     * @return List of ExtCA objects.
     * @throws ExternalCANotFoundException
     *             thrown when no ExtCA exists with given id/name.
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public List<ExtCA> getExtCAsBySubject(final Subject subject) throws ExternalCANotFoundException, ExternalCredentialMgmtServiceException {
        return null;

    }

    /**
     * Check ExtCA name availability.
     *
     * @param name
     *            Name to be verified for the availability.
     * @return true if name is available or else false.
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    @Override
    public boolean isExtCANameAvailable(final String name) throws ExternalCredentialMgmtServiceException {
        logger.debug("Retrieving isExtCANameAvailable {}", name);
        externalCAManagementAuthorizationManager.authorizeIsExternalCANameAvailable();
        CAEntityData caEntityActual = null;
        try {
            caEntityActual = persistenceManager.findEntityByName(CAEntityData.class, name, "certificateAuthorityData.name");
        } catch (final PersistenceException e) {
            logger.debug("Error occured while retrieving external CA data from database using entity name ", e);
            throw new ExternalCredentialMgmtServiceException();
        }
        if (caEntityActual == null || (!caEntityActual.isExternalCA())) {
            return true;
        }
        return false;
    }

    @Override
    public List<String> getTrustProfileByExtCA(final String CAName) throws ExternalCredentialMgmtServiceException, InvalidEntityException {
        externalCAManagementAuthorizationManager.authorizeExternalCAOperations(ActionType.READ);
        CAEntityData caEntityActual = null;
        try {
            caEntityActual = persistenceManager.findEntityByName(CAEntityData.class, CAName, "certificateAuthorityData.name");
            return entitiesManager.getTrustProfileNamesByExtCA(caEntityActual);
        } catch (final PersistenceException | EntityServiceException e) {
            logger.debug("Error occured while retrieving trust profile from external CA data ", e);
            throw new ExternalCredentialMgmtServiceException();
        }

    }
}
