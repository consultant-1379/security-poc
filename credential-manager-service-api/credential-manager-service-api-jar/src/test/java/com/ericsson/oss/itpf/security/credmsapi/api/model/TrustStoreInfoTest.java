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

public class TrustStoreInfoTest {

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo#isValid()} .
     */
    @Test
    public void testIsValid() {

        final TrustStoreInfo tsInfo = new TrustStoreInfo("trustFileLocation", null, TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.BOTH);
        assertTrue("valid trustFileLocation and alias", tsInfo.isValid());

        tsInfo.setAlias("");
        assertFalse("valid trustFileLocation and empty alias", tsInfo.isValid());
        tsInfo.setAlias("alias");

        tsInfo.setCertFormat(null);
        assertTrue("certFormat not valid", !tsInfo.isValid());
        tsInfo.setCertFormat(TrustFormat.JKS);

        tsInfo.setTrustStorePwd(null);
        assertTrue("trustStorePwd not valid", !tsInfo.isValid());
        tsInfo.setTrustStorePwd("trustStorePwd");

        tsInfo.setTrustFileLocation(null);
        assertTrue("neither trustFileLocation or trustFolder are set", !tsInfo.isValid());
        tsInfo.setTrustFileLocation("trustFileLocation");

        tsInfo.setTrustFolder("trustFolder");
        assertFalse("both trustFileLocation and trustFolder set", tsInfo.isValid());

        tsInfo.setTrustFileLocation(null);
        assertTrue("valid trustFolder and alias", tsInfo.isValid());

        //parent not created
        tsInfo.setTrustFolder(null);
        tsInfo.setTrustFileLocation("parent/trustFolder");
        assertFalse("parent directory expected as not created", tsInfo.isValid());
        assertTrue(tsInfo.toString().contains("trustFolder"));

        final File file = new File("parent");

        file.mkdirs(); // creates if not exists
        assertTrue("trustFileLocation not valid", tsInfo.isValid());
        file.delete();

        // test folder
        tsInfo.setTrustFileLocation(null);
        tsInfo.setTrustFolder("/tmp");

        assertTrue("trustFolder not valid", tsInfo.isValid());

        tsInfo.setTrustFolder("/tmp/keyfolder");
        assertTrue("keyStoreFolder not valid", tsInfo.isValid());

        // check delete files in folder
        final File folder = new File("/tmp/keyfolder");
        folder.mkdir();
        final File dummy1 = new File("/tmp/keyfolder/aliasTest.dummy");
        final File dummy2 = new File("/tmp/keyfolder/otherTest.dummy");
        try {
            dummy1.createNewFile();
            dummy2.createNewFile();
        } catch (final IOException e) {
            assertTrue("create File failure", false);
        }

        //delete entries wich name starts with alias
        tsInfo.removeFolderEntries();

        assertFalse("keyStoreFolder file in folder still exist", dummy1.exists());
        assertTrue("keyStoreFolder file in folder not exist", dummy2.exists());
        assertTrue("keyStoreFolder not exist", folder.exists());

        // manually delete the file not matching the alias
        dummy2.delete();

        // tsInfo delete
        tsInfo.delete();
        assertFalse("keyStoreFolder not exist", folder.exists());

        // check delete single truststore file
        tsInfo.setTrustFileLocation("/tmp/anotherTest.dummy");
        final File dummy3 = new File("/tmp/anotherTest.dummy");
        try {
            dummy3.createNewFile();
        } catch (final IOException e) {
            assertTrue("create File failure", false);
        }

        // tsInfo delete
        tsInfo.delete();
        assertTrue("File still exists", !dummy3.exists());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo#isTrustFileLocationValid()} .
     */
    @Test
    public void testIsTrustFileLocationValid() {

        final TrustStoreInfo tsInfo = new TrustStoreInfo("trustFileLocation", null, TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.BOTH);
        assertTrue("trustFileLocation is valid", tsInfo.isTrustFileLocationValid());

        tsInfo.setTrustFileLocation("");
        assertFalse("trustFileLocation is empty", tsInfo.isTrustFileLocationValid());

        tsInfo.setTrustFileLocation(null);
        assertFalse("trustFileLocation is null", tsInfo.isTrustFileLocationValid());
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo#isTrustFolderValid()} .
     */
    @Test
    public void testIsTrustFolderValid() {

        final TrustStoreInfo tsInfo = new TrustStoreInfo(null, "trustFolder", TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.BOTH);
        assertTrue("trustFolder is valid", tsInfo.isTrustFolderValid());

        tsInfo.setTrustFolder("");
        assertFalse("trustFolder is empty", tsInfo.isTrustFolderValid());

        tsInfo.setTrustFolder(null);
        assertFalse("trustFolder is null", tsInfo.isTrustFolderValid());
    }

    @Test
    public void testIsTrustStorePwdValid() {

        final TrustStoreInfo tsInfo = new TrustStoreInfo(null, "trustFolder", TrustFormat.JKS, "trustStorePwd", "alias", TrustSource.BOTH);
        assertTrue("trustStorePwd is valid", tsInfo.isTrustStorePwdValid());

        tsInfo.setTrustStorePwd(null);
        assertFalse("trustStorePwd is not valid", tsInfo.isTrustStorePwdValid());

    }

}
