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
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.services.security.pkimock.exception.MockCertificateServiceException;

public class FileUtilsTest {

    @Test
    public void testdeleteExistingFile() {

        final String filename = "/tmp/paperino.abc";
        final String filenameRenamed = "/tmp/pippo.abc";
        try {
            final PrintWriter writer = new PrintWriter(filename, "UTF-8");
            writer.println("The first line");
            writer.close();
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue(FileUtils.isExist(filename));
        FileUtils.renameTo(filename, filenameRenamed);
        assertTrue(FileUtils.isExist(filenameRenamed));
        FileUtils.delete(filenameRenamed); //method under test
        FileUtils.renameTo(filenameRenamed, filename);
        final Path path = Paths.get(filename);
        if (Files.exists(path)) {
          Assert.assertTrue(false);
        }
    }

    @Test
    public void testdeleteNotExistingFile() {

        final String filename = "/tmp/paperino.abc";
        final Path path = Paths.get(filename);
        try {
            Files.deleteIfExists(path);
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        assertTrue(!FileUtils.isExist(filename));
        FileUtils.delete(filename); //method under test. expect no error
    }
    
    @Test
    public void constructorTest() throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
        Constructor<FileUtils> constr = FileUtils.class.getDeclaredConstructor();
        constr.setAccessible(true);
        FileUtils fiu = constr.newInstance();
        assertTrue(fiu != null);
    }
    
    @Test
    public void testStorageFilesInformation() throws InstantiationException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, NoSuchMethodException, SecurityException {
        //unreliable without changing the final fields because file paths are mostly absolute: no particular asserts here
        Constructor<StorageFilesInformation> constructor;
        constructor = StorageFilesInformation.class.getDeclaredConstructor();
        constructor.setAccessible(true);
        StorageFilesInformation sfInfo = constructor.newInstance();
        assertTrue(sfInfo != null);
        try {
            String KSpath = StorageFilesInformation.getKeystoreFilePath();
            System.out.println(KSpath);
        } catch (MockCertificateServiceException e) {
            //
        }
        try {
            String TSpath = StorageFilesInformation.getTruststoreFilePath();
            System.out.println(TSpath);
        } catch (MockCertificateServiceException e) {
            //
        }
        
//        //We try to change the paths of stores and property, so that they will be found in any case
//        //fields are modified
//        String newStoresPath = System.getProperty("user.dir") + "/src/test/resources/credMStores";
//        String newConfigPath = System.getProperty("user.dir") + "/src/test/resources/config.properties";
//        Field modStoresPath = null;
//        Field modConfigPath = null;
//        String oldStoresPath = "";
//        String oldConfigPath = StorageFilesInformation.FILE_PROPERTIES;
//        Field modifiersField = null;
//        try {
//            modStoresPath = StorageFilesInformation.class.getDeclaredField("JBOSS_EJB_STORES_PATH_DEFAULT");
//            modConfigPath = StorageFilesInformation.class.getDeclaredField("FILE_PROPERTIES");
//            modifiersField = Field.class.getDeclaredField("modifiers");
//            modifiersField.setAccessible(true);
//            modifiersField.setInt(modStoresPath, modStoresPath.getModifiers() & ~Modifier.FINAL);
//            modStoresPath.setAccessible(true);
//            oldStoresPath = (String) modStoresPath.get(null);
//            modStoresPath.set(null, newStoresPath);
//            modifiersField.setInt(modConfigPath, modConfigPath.getModifiers() & ~Modifier.FINAL);
//            modConfigPath.set(null, newConfigPath);
//            
//            System.out.println(StorageFilesInformation.getKeystoreFilePath());
//            System.out.println(StorageFilesInformation.getTruststoreFilePath());
//            
//            //reset to old values
//            modStoresPath.set(null, oldStoresPath);
//            modStoresPath.setAccessible(false);
//            modConfigPath.set(null, oldConfigPath);
//            modifiersField.setAccessible(false);
//        } catch (NoSuchFieldException e) {
//            assertTrue(false);
//        }
    }
}
