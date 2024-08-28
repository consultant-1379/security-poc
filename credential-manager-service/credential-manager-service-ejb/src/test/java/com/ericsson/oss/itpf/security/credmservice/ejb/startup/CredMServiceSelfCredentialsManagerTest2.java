/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.ejb.startup;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Properties;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmservice.util.StorageFilesInformation;

@RunWith(PowerMockRunner.class)
@PrepareForTest({StorageFilesInformation.class,PropertiesReader.class})
public class CredMServiceSelfCredentialsManagerTest2 {

    @InjectMocks
    CredMServiceSelfCredentialsManager credMServiceSelfCredentialsManager;
    
    private static String configPath = "src/test/resources/ericsson/credm/service/data/config.properties";

    @Test
    public void testcheckCertificateValidityExpired() {
        
        Properties configProp = PropertiesReader.getProperties(configPath);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito
            .when(PropertiesReader.getProperties(Matchers.anyString()))
            .thenReturn(configProp);
        
        PowerMockito.mockStatic(StorageFilesInformation.class);

        final String keystoreFileName = "src/test/resources/CredMServiceExpired.jks";
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath()).thenReturn(keystoreFileName);

        assertFalse(CredMServiceSelfCredentialsManager.checkCertificateValidity());
    }

    @Test
    public void testcheckCertificateValidityMissing() {
        
        Properties configProp = PropertiesReader.getProperties(configPath);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito
            .when(PropertiesReader.getProperties(Matchers.anyString()))
            .thenReturn(configProp);
        
        PowerMockito.mockStatic(StorageFilesInformation.class);

        final String keystoreFileName = "src/test/resources/CredMServiceMissing.jks";
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath()).thenReturn(keystoreFileName);

        assertFalse(CredMServiceSelfCredentialsManager.checkCertificateValidity());
    }

    @Test
    public void testcheckCertificateValidityNOTOK() {
        
        Properties configProp = PropertiesReader.getProperties(configPath);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito
            .when(PropertiesReader.getProperties(Matchers.anyString()))
            .thenReturn(configProp);
        
        PowerMockito.mockStatic(StorageFilesInformation.class);

        final String keystoreFileName = "src/test/resources/CredMServiceInvalid.jks";
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath()).thenReturn(keystoreFileName);

        assertFalse(CredMServiceSelfCredentialsManager.checkCertificateValidity());
    }

    @Test
    public void testcheckCertificateValidityOK() {
        
        Properties configProp = PropertiesReader.getProperties(configPath);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito
            .when(PropertiesReader.getProperties(Matchers.anyString()))
            .thenReturn(configProp);
        
        PowerMockito.mockStatic(StorageFilesInformation.class);

        final String keystoreFileName = "src/test/resources/CredMService.jks";
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath()).thenReturn(keystoreFileName);

        assertTrue(CredMServiceSelfCredentialsManager.checkCertificateValidity());
    }

}
