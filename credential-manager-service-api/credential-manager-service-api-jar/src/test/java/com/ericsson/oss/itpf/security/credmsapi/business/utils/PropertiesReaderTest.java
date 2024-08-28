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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Properties;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ConfigurationException;

public class PropertiesReaderTest {

    @Test(expected = ConfigurationException.class)
    public void testGetPropertiesOfNotExistingFile() throws ConfigurationException {
        PropertiesReader pr = new PropertiesReader(); //just to cover
        assertTrue(pr != null);
        PropertiesReader.getProperties("puzza.config");
    }

    @Test()
    public void testGetPropertiesOfConfigFile() throws ConfigurationException {
        final Properties props = PropertiesReader.getConfigProperties();
        assertEquals(3, props.size());
    }
    
    @Test
    public void testGetPropertiesMisc() throws ConfigurationException, IOException {
        PropertiesReader.getProperties("");
        File prop = new File("/tmp/prop1.properties");
        prop.createNewFile();
        PropertiesReader.getProperties("/tmp/prop1.properties");
        assertTrue(prop.delete());
    }
    
    @Test
    public void testGetPropertiesMisc1() throws IOException {
        File prop = new File("/tmp/prop2.properties");
        prop.createNewFile();
        prop.setReadable(false, true);
        try {
            PropertiesReader.getProperties("/tmp/prop2.properties");
        } catch(ConfigurationException e) {
            assertTrue(true);
        }
        prop.setReadable(true, true);
        assertTrue(prop.delete());
    }

}
