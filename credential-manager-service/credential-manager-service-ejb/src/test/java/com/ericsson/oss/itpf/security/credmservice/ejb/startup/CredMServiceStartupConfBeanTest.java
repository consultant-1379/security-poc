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

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerStartupException;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmservice.util.StorageFilesInformation;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ StorageFilesInformation.class, PropertiesReader.class })
@PowerMockIgnore("javax.management.*")
public class CredMServiceStartupConfBeanTest {

    final static String configDestName = "/tmp/config.properties";
    final static String jbossCertTrustPath = "/ericsson/credm/service/data/certs/";

    @BeforeClass
    public static void cleanup() throws IOException {
        Files.deleteIfExists(Paths.get("/tmp/" + StorageFilesInformation.FILE_PROPERTIES));
    }

    @Before
    public void setup() {
        StorageFilesInformation.outputPath = null;
        //copy config.properties in src/test/resource in /tmp/<servicePATH>/config.properties
        copyFileFromResources(this, StorageFilesInformation.FILE_PROPERTIES, configDestName);
    }

    @After
    public void shutDown() {
        CredMServiceStartupConfBeanTest.deleteFile(configDestName);
    }

    @Test
    public void getKeystoreFilePathTest() {
        // PowerMockito.when(MBeanManager.getJBossConfigPath()).thenReturn(
        // "donald/duck");
        final String filepath = StorageFilesInformation.getKeystoreFilePath();
        Assert.assertTrue((jbossCertTrustPath + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT).equals(filepath));
    }

    @Test
    public void getTruststoreFilePathTest() {
        // PowerMockito.mockStatic(MBeanManager.class);
        // PowerMockito.when(MBeanManager.getJBossConfigPath()).thenReturn("donald/duck");
        final String filepath = StorageFilesInformation.getTruststoreFilePath();
        Assert.assertTrue((jbossCertTrustPath + StorageFilesInformation.JBOSS_EJB_TRUST_STORE_FILE_DEFAULT).equals(filepath));
    }

    @Test
    public void getKeystoreAliasNameTest() {
        final String alias = CredMServiceSelfCredentialsManager.getKeystoreAliasName();
        Assert.assertTrue(CredMServiceSelfCredentialsManager.JBOSS_EJB_KEY_ALIAS_DEFAULT.equals(alias));
    }

    @Test
    public void getKeystorePasswordTest() {
        String password = null;
        final Properties configProp = PropertiesReader.getProperties(configDestName);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito.when(PropertiesReader.getProperties(Matchers.anyString())).thenReturn(configProp);

        try {
            password = CredMServiceSelfCredentialsManager.getKeystoresPassword();
        } catch (final CredentialManagerStartupException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
        Assert.assertTrue("secret".equals(password));
    }

    @Test
    public void checkCertificateValidityOkTest()
            throws CredentialManagerStartupException, IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException {
        final String destName = "/tmp/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT;
        copyFileFromResources(this, "/CredMServiceStartupConfBeanTest/aliascredmservice/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT,
                destName);

        PowerMockito.mockStatic(StorageFilesInformation.class);
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath())
                .thenReturn("/tmp/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT);

        final Properties configProp = PropertiesReader.getProperties(configDestName);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito.when(PropertiesReader.getProperties(Matchers.anyString())).thenReturn(configProp);

        final CredMServiceStartupConfBean bean = new CredMServiceStartupConfBean();
        Assert.assertTrue(CredMServiceSelfCredentialsManager.checkCertificateValidity());

        deleteFile(destName);
    }

    @Test
    public void checkCertificateValidityAliasNotValidTest() {
        final String destName = "/tmp/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT;
        CredMServiceStartupConfBeanTest.copyFileFromResources(this,
                "/CredMServiceStartupConfBeanTest/aliaspippo/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT, destName);

        PowerMockito.mockStatic(StorageFilesInformation.class);
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath())
                .thenReturn("/tmp/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT);
        final Properties configProp = PropertiesReader.getProperties(configDestName);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito.when(PropertiesReader.getProperties(Matchers.anyString())).thenReturn(configProp);
        final CredMServiceStartupConfBean bean = new CredMServiceStartupConfBean();
        Assert.assertTrue(!CredMServiceSelfCredentialsManager.checkCertificateValidity());

        CredMServiceStartupConfBeanTest.deleteFile(destName);
    }

    @Test
    public void checkCertificateValidityExpiredTest() {
        final String destName = "/tmp/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT;
        CredMServiceStartupConfBeanTest.copyFileFromResources(this,
                "/CredMServiceStartupConfBeanTest/expired/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT, destName);

        PowerMockito.mockStatic(StorageFilesInformation.class);
        PowerMockito.when(StorageFilesInformation.getKeystoreFilePath())
                .thenReturn("/tmp/" + StorageFilesInformation.JBOSS_EJB_KEY_STORE_FILE_DEFAULT);
        final Properties configProp = PropertiesReader.getProperties(configDestName);
        PowerMockito.mockStatic(PropertiesReader.class);
        PowerMockito.when(PropertiesReader.getProperties(Matchers.anyString())).thenReturn(configProp);
        final CredMServiceStartupConfBean bean = new CredMServiceStartupConfBean();
        Assert.assertTrue(!CredMServiceSelfCredentialsManager.checkCertificateValidity());

        CredMServiceStartupConfBeanTest.deleteFile(destName);
    }

    @Test
    public void credMServiceStartupConfBeanMethodsTest() {

        final CredMServiceStartupConfBean localcSSCB = new CredMServiceStartupConfBean();
        localcSSCB.credmServiceStartupProcedure();
        localcSSCB.setRestEnabled(false);
        assertTrue(!localcSSCB.isEnabled());
        localcSSCB.setRestEnabled(true);
        assertTrue(localcSSCB.isEnabled());

    }

    /**************************
     * ********************* ***** UTILITIES ****
     ***********************
     *************************/

    private static void deleteFile(final String destName) {
        final Path path = Paths.get(destName);
        try {
            Files.delete(path);
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private static void copyFileFromResources(final Object obj, final String srcFile, final String destName) {
        final File targetFile = new File(destName);
        try (final OutputStream outStream = new FileOutputStream(targetFile)) {
            final InputStream input = obj.getClass().getResourceAsStream(srcFile);
            final byte[] buffer = new byte[input.available()];
            input.read(buffer);
            outStream.write(buffer);
        } catch (final IOException e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }
}
