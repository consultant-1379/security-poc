/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.credentialsmanagement.helper;

import java.net.InetAddress;
import java.net.UnknownHostException;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.constants.Constants;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SdkResourceManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.ProfileManager;

/**
 * This class will provide the following helper methods for PKICredentialsManagement service to create Entity if not exist, to save file content in the specified path, to check for file exist and
 * Resolve host name.
 * 
 * @author tcsnapa
 */
public class CredentialsHelper {

    @EServiceRef
    SdkResourceManagementLocalService sdkResourceManagementLocalService;
    @Inject
    private ProfileManager profileManager;

    @Inject
    EntitiesManager entitiesManager;

    @Inject
    private Logger logger;

    /**
     * This method will check for entity with the given entity name and creates if not exist in the pki-manager data base.
     * 
     * @param entityName
     *            is the name of the entity.
     * @param subjectDN
     *            is the given distinguish name which is to be set to entity.
     * @param entityProfileName
     *            is the name of the profile using which the entity is to be created in pki-manager data base.
     * @param keyGenerationAlgorithm
     *            is the Algorithm which is to be set to the entity while entity preparation.
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while checking entity name or entity profile existence in the pki-manager data base or while creating Entity.
     */
    public void createEntityIfNotExist(final String entityName, final String subjectDN, final String entityProfileName, final Algorithm keyGenerationAlgorithm)
            throws CredentialsManagementServiceException {
        EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(entityProfileName);
        try {
            entityProfile = profileManager.getProfile(entityProfile);
        } catch (final ProfileException e) {
            logger.error("{} profile not available to generate pki-manager credentials.", entityProfileName);
            throw new CredentialsManagementServiceException(e.getMessage(), e);
        }
        try {
            final boolean entityNameAvailable = entitiesManager.isNameAvailable(entityName.trim(), EntityType.ENTITY);
            if (entityNameAvailable) {
                final Entity entity = setupEntity(entityName, subjectDN, entityProfile, keyGenerationAlgorithm);
                entitiesManager.createEntity(entity);
            }
        } catch (final EntityException | AlgorithmException | ProfileException | CertificateException | CRLException exception) {
            logger.error("Unable to create entity to generate pki-manager credentials {}", exception.getMessage());
            throw new CredentialsManagementServiceException(ErrorMessages.UNABLE_TO_CREATE_ENTITY, exception);
        }
    }

    private Entity setupEntity(final String entityName, final String subjectDN, final EntityProfile entityProfile, final Algorithm keyGenerationAlgorithm) {
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        final Subject subject = new Subject();
        subject.fromASN1String(subjectDN);
        entityInfo.setSubject(subject);
        final Entity entity = new Entity();
        entity.setEntityProfile(entityProfile);
        entity.setEntityInfo(entityInfo);
        entity.setCategory(entityProfile.getCategory());
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        return entity;
    }

    /**
     * This method will create a file with the given file content at the given file path.
     * 
     * @param fileContent
     *            is the byte array of content to be write into the file.
     * @param filePath
     *            is the location where to store the file.
     * @throws CredentialsManagementServiceException
     *             is thrown when error occurs while doing file operations.
     */
    public void saveFile(final byte[] fileContent, final String filePath) {
        sdkResourceManagementLocalService.write(filePath, fileContent, false);
    }

    /**
     * This method will return true if the file exists at the given file path.
     * 
     * @param filePath
     *            is the location of the file.
     * @return boolean, true if file exists else false.
     */
    public boolean checkForFileExist(final String filePath) {
        return sdkResourceManagementLocalService.isResourceExist(filePath);
    }

    /**
     * This method will read the server host name and replace the same in the given String with the given Constants.HOST_NAME_STRING.
     * 
     * @param sourceString
     *            is the string in which the Constants.HOST_NAME_STRING replaced with the Server's host name.
     * @return String is the
     */
    // TODO TORF-93256 secure communication SPS and RA final/TORF-99190 -split this method into two parts, getHostName in pki-common and resolve in this class
    public String resolveHostName(final String sourceString) {
        String host = "";
        if (sourceString.toUpperCase().contains(Constants.HOST_NAME_STRING)) {
            try {
                host = InetAddress.getLocalHost().getHostName();
            } catch (final UnknownHostException e) {
                logger.error("Failed to read Server host name");
                throw new CredentialsManagementServiceException(ErrorMessages.FAILED_TO_READ_HOST_NAME, e);
            }
        }
        if (host != "" && host != null) {
            return sourceString.toUpperCase().replace((Constants.HOST_NAME_STRING), host);
        } else {
            logger.error("Failed to read host name");
            throw new CredentialsManagementServiceException(ErrorMessages.FAILED_TO_READ_HOST_NAME);
        }
    }
}
