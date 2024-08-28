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
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;

import org.junit.Test;

public class KeystoreInfoTest {

    //    @Before
    //    public  void createFiles()
    //    {   
    //        try {
    // 
    //              File file = new File("keyAndCertLocation");
    // 
    //              if (file.createNewFile()){
    //                System.out.println("File is created!");
    //              }else{
    //                System.out.println("File already exists.");
    //              }
    // 
    //        } catch (IOException e) {
    //              e.printStackTrace();
    //        }
    //    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo#isValid()} .
     */
    @Test
    public void testIsValid() throws IOException {

        final KeystoreInfo ksInfo = new KeystoreInfo("keyAndCertLocation", null, null, null, CertificateFormat.JKS, "", "alias");
        assertTrue("valid keyAndCertLocation and alias", ksInfo.isValid());

        ksInfo.setAlias("");
        assertFalse("valid keyAndCertLocation and empty alias", ksInfo.isValid());

        ksInfo.setAlias("alias");

        ksInfo.setCertFormat(null);
        assertTrue("certFormat not valid", !ksInfo.isValid());

        ksInfo.setCertFormat(CertificateFormat.JKS);

        ksInfo.setKeyStorePwd(null);
        assertTrue("keyStorePwd not valid", !ksInfo.isValid());

        ksInfo.setKeyStorePwd("");
        ksInfo.setKeyStoreFolder("keyStoreFolder");
        assertFalse("both keyAndCertLocation and keyStoreFolder set", ksInfo.isValid());

        ksInfo.setKeyStoreFolder("");
        ksInfo.setCertificateLocation("certificateLocation");
        ksInfo.setPrivateKeyLocation("privateKeyLocation");
        ksInfo.setCertFormat(CertificateFormat.BASE_64);
        assertFalse("both keyAndCertLocation and certificateLocation set", ksInfo.isValid());

        ksInfo.setKeyAndCertLocation("");
        assertTrue("keyAndCertLocation empty and certificateLocation set", ksInfo.isValid());

        ksInfo.setKeyStoreFolder("keyStoreFolder");
        ksInfo.setCertificateLocation("");
        ksInfo.setPrivateKeyLocation("");
        assertTrue("keyAndCertLocation empty, certificateLocation empty and keyStoreFolder set", ksInfo.isValid());

        ksInfo.setCertificateLocation("certificateLocation");
        ksInfo.setPrivateKeyLocation("privateKeyLocation");
        assertFalse("keyAndCertLocation empty, certificateLocation set and keyStoreFolder set", ksInfo.isValid());

        ksInfo.setCertificateLocation("");
        ksInfo.setPrivateKeyLocation("");
        ksInfo.setKeyAndCertLocation("keyAndCertLocation");
        assertFalse("valid keyAndCertLocation and file couple empty and keyStoreFolder set", ksInfo.isValid());

        ksInfo.setKeyStoreFolder("");
        assertTrue("valid keyAndCertLocation and file couple empty and keyStoreFolder empty", ksInfo.isValid());

        ksInfo.setKeyAndCertLocation("");
        assertTrue("No location set", !ksInfo.isValid());

        ksInfo.setKeyAndCertLocation("parent/keyAndCertLocation");
        assertFalse("parent directory expected as not created", ksInfo.isValid());

        final File file = new File("parent");

        file.mkdirs(); // creates if not exists
        assertTrue("keyAndCertLocation not valid", ksInfo.isValid());

        file.delete();

        ksInfo.setKeyAndCertLocation("");
        ksInfo.setKeyStoreFolder("/tmp");
        assertTrue("keyStoreFolder not valid", ksInfo.isValid());

        ksInfo.setKeyStoreFolder("/tmp/keyfolder");
        assertTrue("keyStoreFolder not valid", ksInfo.isValid());

    }

    /*
     * public KeystoreInfo(String keyAndCertLocation, String privateKeyLocation, String certificateLocation, String keyStoreFolder, CertificateFormat certFormat, String keyStorePwd, String alias) {
     */
    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo#isKeyAndCertLocationValid()} .
     */
    @Test
    public void testIsKeyAndCertLocationValid() {

        final KeystoreInfo ksInfo = new KeystoreInfo("keyAndCertLocation", null, null, null, null, null, null);
        assertTrue("keyAndCertLocation is valid", ksInfo.isKeyAndCertLocationValid());

        ksInfo.setKeyAndCertLocation("");
        assertFalse("keyAndCertLocation is empty", ksInfo.isKeyAndCertLocationValid());

        ksInfo.setKeyAndCertLocation(null);
        assertFalse("keyAndCertLocation is null", ksInfo.isKeyAndCertLocationValid());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo#isKeyStoreFolderValid()} .
     */
    @Test
    public void testIsKeyStoreFolderValid() {

        final KeystoreInfo ksInfo = new KeystoreInfo(null, null, null, "keyStoreFolder", null, null, null);
        assertTrue("keyStoreFolder is valid", ksInfo.isKeyStoreFolderValid());

        ksInfo.setKeyStoreFolder("");
        assertFalse("keyStoreFolder is empty", ksInfo.isKeyStoreFolderValid());

        ksInfo.setKeyStoreFolder(null);
        assertFalse("keyStoreFolder is null", ksInfo.isKeyStoreFolderValid());

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo#isFileCoupleValid()} .
     */
    @Test
    public void testIsFileCoupleValid() {

        final KeystoreInfo ksInfo = new KeystoreInfo(null, "privateKeyLocation", "certificateLocation", null, CertificateFormat.BASE_64, null, null);
        assertTrue("file couple is valid", ksInfo.isFileCoupleValid());

        ksInfo.setCertFormat(CertificateFormat.JKS);
        assertFalse("certificate format not BASE_64", ksInfo.isFileCoupleValid());

        ksInfo.setCertFormat(CertificateFormat.BASE_64);
        ksInfo.setPrivateKeyLocation(null);
        assertFalse("only privateKeyLocation is null", ksInfo.isFileCoupleValid());

        ksInfo.setPrivateKeyLocation("privateKeyLocation");
        ksInfo.setCertificateLocation(null);
        assertFalse("only certificateLocation is null", ksInfo.isFileCoupleValid());

        ksInfo.setPrivateKeyLocation("");
        ksInfo.setCertificateLocation("");
        assertFalse("both privateKeyLocation and certificateLocation is empty", ksInfo.isFileCoupleValid());
    }

    @Test
    public void testIsKeyStorePwdValid() {

        final KeystoreInfo ksInfo = new KeystoreInfo(null, "privateKeyLocation", "certificateLocation", null, CertificateFormat.BASE_64, null, null);
        assertFalse("KeyStorePwd is not valid", ksInfo.isKeyStorePwdValid());

        ksInfo.setKeyStorePwd("");
        assertTrue("KeyStorePwd is valid", ksInfo.isKeyStorePwdValid());
    }

    @Test
    public void testDelete() {

        final KeystoreInfo ksInfo = new KeystoreInfo("/tmp/keyAndCertLocation", "/tmp/privateKeyLocation", "/tmp/certificateLocation", "/tmp/keyStoreFolder", CertificateFormat.BASE_64, null, "test");

        /**
         * create files and directory
         */
        final File keyAndCertLocation = new File("/tmp/keyAndCertLocation");
        final File privateKeyLocation = new File("/tmp/privateKeyLocation");
        final File certificateLocation = new File("/tmp/certificateLocation");
        final File keyStoreFolder = new File("/tmp/keyStoreFolder");
        try {
            keyAndCertLocation.createNewFile();
            privateKeyLocation.createNewFile();
            certificateLocation.createNewFile();
            keyStoreFolder.mkdir();
            final File file1 = new File("/tmp/keyStoreFolder/" + ksInfo.getAlias() + "File1");
            file1.createNewFile();
            final File file2 = new File("/tmp/keyStoreFolder/" + ksInfo.getAlias() + "File2");
            file2.createNewFile();
            final File file3 = new File("/tmp/keyStoreFolder/" + ksInfo.getAlias() + "File3");
            file3.createNewFile();
        } catch (final IOException e) {
            assertTrue("Error during file(s) creation", false);
        }

        ksInfo.delete();

        assertTrue("testDelete failed", !keyStoreFolder.exists() && (keyStoreFolder.length() == 0) && !keyAndCertLocation.exists() && !privateKeyLocation.exists() && !certificateLocation.exists());

    }
}
