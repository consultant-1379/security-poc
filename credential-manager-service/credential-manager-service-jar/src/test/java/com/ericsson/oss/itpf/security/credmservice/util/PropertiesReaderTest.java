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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.junit.Assert;
import org.junit.Test;

public class PropertiesReaderTest {

    private static final String TEST_PROPERTY_NAME = "answer.to.the.ultimate.question";
    private static final String TEST_PROPERTY_VALUE = "42";
    private static final String TEST_PROPERTY_NAME_CREDMSERVICE = "path.xml.entities.schema";
    private static final String TEST_PROPERTY_VALUE_CREDMSERVICE = "EntitiesSchema.xsd";
    private static final String UNITTEST_PROPERTY_FILE = "unittest.properties";

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader#getConfigProperties()}.
     */
    @Test
    public final void testGetConfigProperties() {
        final String prop = PropertiesReader.getConfigProperties().getProperty(TEST_PROPERTY_NAME_CREDMSERVICE);
        Assert.assertTrue(TEST_PROPERTY_VALUE_CREDMSERVICE.equals(prop));
    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader#getProperties(java.lang.String)}.
     */
    @Test
    public final void testGetPropertiesFromClasspath() {
        final String prop = PropertiesReader.getProperties(UNITTEST_PROPERTY_FILE).getProperty(TEST_PROPERTY_NAME);
        Assert.assertTrue(TEST_PROPERTY_VALUE.equals(prop));
    }

    @Test
    public final void testGetPropertiesFromClasspathWithSeparator() {
        final String prop = PropertiesReader.getProperties("/" + UNITTEST_PROPERTY_FILE).getProperty(TEST_PROPERTY_NAME);
        Assert.assertTrue(TEST_PROPERTY_VALUE.equals(prop));
    }

    @Test
    public final void testGetPropertiesFromTmp() {
        final Path destination = Paths.get("/tmp/credmserviceunittest.properties");
        try {
            final InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(UNITTEST_PROPERTY_FILE);
            Files.copy(in, destination);

            final String prop = PropertiesReader.getProperties("credmserviceunittest.properties").getProperty(TEST_PROPERTY_NAME);
            Assert.assertTrue(TEST_PROPERTY_VALUE.equals(prop));
        } catch (final IOException e) {
            e.printStackTrace();
        } finally {
            try {
                Files.deleteIfExists(destination);
            } catch (final IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    @Test
    public final void testGetPropertiesFromFullPath() {
        final Path destination = Paths.get("/tmp/credmserviceunittest.properties");
        try {
            final InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(UNITTEST_PROPERTY_FILE);
            Files.copy(in, destination);

            final String prop = PropertiesReader.getProperties("/tmp/credmserviceunittest.properties").getProperty(TEST_PROPERTY_NAME);
            Assert.assertTrue(TEST_PROPERTY_VALUE.equals(prop));
        } catch (final IOException e) {
            e.printStackTrace();
        } finally {
            try {
                Files.deleteIfExists(destination);
            } catch (final IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }
}
