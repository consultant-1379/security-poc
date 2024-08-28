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
package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.Properties;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

@RunWith(JUnit4.class)
public class PropertiesReaderTest {
    
    @Test
    public void test1 () {
        
        final Properties configProperties = PropertiesReader.getConfigProperties();
        final Properties log4jProperties = PropertiesReader.getProperties(configProperties
                .getProperty("log4j"));        
        assertTrue("PropertiesReaderTest", log4jProperties!= null);

        final String wrongPropStr = configProperties.getProperty("xxxxxx");        
        assertTrue("PropertiesReaderTest", wrongPropStr == null);

        Properties wrongProperties = null;
        try {
            wrongProperties = PropertiesReader.getProperties("xxx");
        } catch (final Exception e) {
            assertTrue("PropertiesReaderTest", wrongProperties == null);
        }
        
        Properties wrongConfigProperties = null;
        try {
            wrongConfigProperties = PropertiesReader.getProperties("pippo");
        } catch (final Exception e) {
            assertTrue("PropertiesReaderTest", wrongConfigProperties == null);
        }
    }

    @Test
    public void test2 () {
        
        // test the various postions where the file can be found:
        // absolute path
        final File file1 = new File("/tmp/here.tmp");
        try {
            file1.createNewFile();
        } catch (final IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        final Properties properties1 = PropertiesReader.getProperties(file1.getAbsolutePath());        
        assertTrue("PropertiesReaderTest", properties1 != null);
        file1.delete();
        
        // test the various postions where the file can be found:
        // in ../conf/ (or in /resourses for debug)
//        final String workingDir = System.getProperty("user.dir");
//        System.out.println("Current working directory : " + workingDir);
//        final File file2 = new File(workingDir + "/target/resources/here.tmp");
// 
//            try {
//                file2.createNewFile();
//            } catch (final IOException e) {
//                // TODO Auto-generated catch block
//                e.printStackTrace();
//            }
//
//        final Properties properties2 = PropertiesReader.getProperties(file2.getName());        
//        assertTrue("PropertiesReaderTest", properties2 != null);
//        file2.delete();
       
    }

}
