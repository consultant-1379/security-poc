package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.generator;

import static org.junit.Assert.assertNotNull;

import org.junit.Before;
import org.junit.Test;

public class SerialNumberGeneratorTest {

    SerialNumberGenerator serialNumberGenerator;

    /**
     * Prepares initial data.
     */
    @Before
    public void setUp() {

        serialNumberGenerator = new SerialNumberGenerator();
    }

    /**
     * Method to test generation of serial number of certificate.
     */
    @Test
    public void testGenerateSerialNumber() {

        final String serialNumber = serialNumberGenerator.generateSerialNumber();
        assertNotNull(serialNumber);
    }
}
