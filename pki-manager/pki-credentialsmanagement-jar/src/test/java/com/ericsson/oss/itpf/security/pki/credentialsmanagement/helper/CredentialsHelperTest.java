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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.net.UnknownHostException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.ProfileException;
import com.ericsson.oss.itpf.security.pki.manager.local.service.api.SdkResourceManagementLocalService;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.ProfileManager;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
public class CredentialsHelperTest {
    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    private ProfileManager profileManager;

    @Mock
    Resource resource;

    @Mock
    private Logger logger;

    @Mock
    EntitiesManager entitiesManager;

    @InjectMocks
    CredentialsHelper credentialsHelper;

    @Mock
    SdkResourceManagementLocalService sdkResourceManagementLocalService;

    private String entityName = "ENM_SubCA";
    private String subjectDN = "CN= ARJ_Root";
    private String entityProfileName = "SubCA_Entity_Profile";
    private Algorithm keyGenerationAlgorithm = new Algorithm();
    boolean entityNameAvailable = false;

    @Before
    public void setUpData() {

        keyGenerationAlgorithm.setName("RSA");
        keyGenerationAlgorithm.setSupported(true);

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(Resources.getFileSystemResource("filePath")).thenReturn(resource);
    }

    /**
     * Method to test CreateEntityIfNotExist.
     */

    @Test
    public void testCreateEntityIfNotExist() {
        Entity entity = new Entity();
        EntityProfile entityProfile = new EntityProfile();

        entityProfile.setName(entityProfileName);

        Mockito.when(entitiesManager.isNameAvailable(entityName.trim(), EntityType.ENTITY)).thenReturn(true);
        Mockito.when(entitiesManager.createEntity(entity)).thenReturn(entity);

        Mockito.when(profileManager.getProfile(entityProfile)).thenReturn(entityProfile);
        credentialsHelper.createEntityIfNotExist(entityName, subjectDN, entityProfileName, keyGenerationAlgorithm);
        Mockito.verify(entitiesManager).isNameAvailable(entityName.trim(), EntityType.ENTITY);
    }

    @Test(expected = CredentialsManagementServiceException.class)
    public void testCreateEntityIfNotExist_ProfileException() {

        Entity entity = new Entity();
        EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(entityProfileName);

        Mockito.when(entitiesManager.isNameAvailable(entityName.trim(), EntityType.ENTITY)).thenReturn(true);

        Mockito.when(entitiesManager.createEntity(entity)).thenReturn(entity);

        Mockito.when(profileManager.getProfile(entityProfile)).thenThrow(new ProfileException(" profile not available to generate pki-manager credentials."));
        credentialsHelper.createEntityIfNotExist(entityName, subjectDN, entityProfileName, keyGenerationAlgorithm);

    }

    @Test(expected = CredentialsManagementServiceException.class)
    public void testCreateEntityIfNotExist_EntityException() {

        EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName(entityProfileName);

        Mockito.when(entitiesManager.isNameAvailable(entityName.trim(), EntityType.ENTITY)).thenReturn(true);

        Mockito.when(profileManager.getProfile(entityProfile)).thenReturn(entityProfile);

        Mockito.when(entitiesManager.isNameAvailable(entityName.trim(), EntityType.ENTITY)).thenThrow(new EntityException("Unable to create entity to generate pki-manager credentials"));

        credentialsHelper.createEntityIfNotExist(entityName, subjectDN, entityProfileName, keyGenerationAlgorithm);

    }

    /**
     * Method to test SaveFile.
     * 
     * @throws IOException
     */
    @Test
    public void testSaveFile() throws IOException {

        PowerMockito.when(resource.supportsWriteOperations()).thenReturn(true);
        PowerMockito.when(resource.write("".getBytes(), false)).thenReturn(0);
        credentialsHelper.saveFile("fileContent".getBytes(), "filePath");
    }

    /**
     * Method to test CheckForFileExist.
     * 
     * @throws IOException
     */
    @Test
    public void testCheckForFileExist() throws IOException {

        PowerMockito.when(sdkResourceManagementLocalService.isResourceExist("filePath")).thenReturn(true);
        boolean fileExists = credentialsHelper.checkForFileExist("filePath");
        assertTrue(fileExists);
    }

    /**
     * Method to test ResolveHostName
     * 
     * @throws UnknownHostException
     */
    @Test
    public void testResolveHostName() throws UnknownHostException {
        String resolveHostName = credentialsHelper.resolveHostName("##HOSTNAME##");
        assertNotNull(resolveHostName);
    }
}
