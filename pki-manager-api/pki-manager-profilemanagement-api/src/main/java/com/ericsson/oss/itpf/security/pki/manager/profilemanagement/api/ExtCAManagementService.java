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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;

/**
 * This is an interface for extCA management service and provides API's for below operations.
 * <ul>
 * <li>Importing extCAs in bulk manner.</li>
 * <li>CRUD of extCAs</li>
 * <li>Fetch,validate and update of the OTP of an entity</li>
 * </ul>
 */
@EService
@Remote
public interface ExtCAManagementService {

    /**
     * Get an ExtCA based on ExtCA Id/name.
     *
     * @param extCA
     *            Object of ExtCA with id/name set.
     * @return Returns object of ExtCA.
     *
     * @throws ExternalCANotFoundException
     *             thrown when no extCA exists with given id/name.
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     *
     */
    ExtCA getExtCA(ExtCA extCA) throws ExternalCANotFoundException, ExternalCredentialMgmtServiceException;

    /**
     * Get all extCAs .
     *
     * @return List of ExtCA objects.
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    List<ExtCA> getExtCAs() throws ExternalCredentialMgmtServiceException;

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
    List<ExtCA> getExtCAsBySubject(Subject subject) throws ExternalCANotFoundException, ExternalCredentialMgmtServiceException;

    /**
     * Check ExtCA name availability.
     *
     * @param name
     *            Name to be verified for the availability.
     * @return true if name is available or else false.
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    boolean isExtCANameAvailable(String name) throws ExternalCredentialMgmtServiceException;

    /**
     * Get TrustProfiles for a given CAName.
     *
     * @param CAName
     *            Name of CA entity
     * @return the list of TrustProfiles name for a given CA
     * @throws ExternalCredentialMgmtServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is other than caentity/entity.
     */
    List<String> getTrustProfileByExtCA(String CAName) throws ExternalCredentialMgmtServiceException, InvalidEntityException;

}
