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
package com.ericsson.oss.itpf.security.pki.common.keystore;

import static org.junit.Assert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

/**
 * This class is a junit test class for KeyStoreInfoTest class.
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class KeyStoreInfoTest {

    @InjectMocks
    KeyStoreInfo keyStoreInfo;

    private KeyStoreType keyStoreType;

    private String aliasName = "lteipsecnecus";
    private String filePath = "src/test/resources/LTEIPSecNEcus_Sceprakeystore_1.p12";
    private String password = "C4bCzXyT";
    String fileType = "PKCS12";

    /**
     * Test case for checking equals() and hashCode() method.
     * 
     */
    @Test
    public void testEqualsAndHashCodeSuccess() {
        KeyStoreInfo obj1 = new KeyStoreInfo(filePath, KeyStoreType.valueOf(fileType), password, aliasName);
        KeyStoreInfo obj2 = new KeyStoreInfo(filePath, KeyStoreType.valueOf(fileType), password, aliasName);
        assertTrue(obj1.equals(obj2) && obj2.equals(obj1));
        assertTrue(obj1.hashCode() == obj2.hashCode());
    }

    /**
     * Test case for checking equals() and hashCode() method Fail scenario.
     * 
     */
    @Test
    public void testEqualsAndHashCodeFail() {
        KeyStoreInfo obj1 = new KeyStoreInfo(filePath, KeyStoreType.valueOf(fileType), password, aliasName);
        KeyStoreInfo obj2 = new KeyStoreInfo(filePath, KeyStoreType.valueOf(fileType), null, null);
        KeyStoreInfo obj3 = new KeyStoreInfo(null, KeyStoreType.valueOf(fileType), null, aliasName);
        KeyStoreInfo obj4 = new KeyStoreInfo(filePath, KeyStoreType.valueOf(fileType), null, aliasName);
        KeyStoreInfo obj5 = new KeyStoreInfo(filePath, KeyStoreType.valueOf("JKS"), null, aliasName);
        assertFalse(obj1.equals(obj2) && obj2.equals(obj1));
        assertFalse(obj1.equals(obj3) && obj3.equals(obj1));
        assertFalse(obj1.equals(obj4) && obj4.equals(obj1));
        assertFalse(obj1.equals(obj5) && obj5.equals(obj1));
        assertFalse(obj1.hashCode() == obj2.hashCode());
    }

    /**
     * Test case for checking setFilePath() method.
     * 
     */
    @Test
    public void testSetFilePath() {
        String filePath = "src/test/resources/LTEIPSecNEcus_Sceprakeystore_1.p12";
        keyStoreInfo.setFilePath(filePath);
        assertEquals(keyStoreInfo.getFilePath(), filePath);

    }

    /**
     * Test case for checking setkeyStoreType() method.
     * 
     */
    @Test
    public void testSetKeyStoreType() {
        String fileType = "PKCS12";
        keyStoreType = KeyStoreType.valueOf(fileType);
        keyStoreInfo.setKeyStoreType(keyStoreType);
        assertEquals(keyStoreInfo.getKeyStoreType(), keyStoreType);

    }

    /**
     * Test case for checking setAliasName() method.
     * 
     */
    @Test
    public void testSetAliasName() {
        String aliasName = "lteipsecnecus";
        keyStoreInfo.setAliasName(aliasName);
        assertEquals(keyStoreInfo.getAliasName(), aliasName);
    }

    /**
     * Test case for checking setPassword() method.
     * 
     */
    @Test
    public void testSetPassword() {
        String password = "C4bCzXyT";
        keyStoreInfo.setPassword(password);
        assertEquals(keyStoreInfo.getPassword(), password);
    }

}
