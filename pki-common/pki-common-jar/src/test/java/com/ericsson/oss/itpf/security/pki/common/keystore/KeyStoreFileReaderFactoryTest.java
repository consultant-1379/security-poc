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

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.setUp.KeyStoreSetUP;

/**
 * This class is a junit test class for KeyStoreFileReaderFactory
 * 
 * @author tcshepa
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class KeyStoreFileReaderFactoryTest extends KeyStoreSetUP {

    @InjectMocks
    KeyStoreFileReaderFactory keyStoreFileReaderFactory;

    @Mock
    private KeyStoreFileReader keyStoreFileReader;

    @Mock
    private Logger logger;

    private String validFileType = "PKCS12";
    private String validAliasName = "lteipsecnecus";

    /**
     * Test case for checking getKeystoreFileReaderInstance() method.
     * 
     */
    @Test
    public void testGetKeyStoreFileReaderInstance() {
        keyStoreFileReader = keyStoreFileReaderFactory.getKeystoreFileReaderInstance(getKeyStoreInfo(validFileType, validAliasName));
        assertEquals("JksPkcs12KeyStoreFileReader", keyStoreFileReader.getClass().getSimpleName());
    }

}
