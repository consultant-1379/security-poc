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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class BasicConstraintsBuilderTest extends BaseTest {

    @InjectMocks
    private BasicConstraintsBuilder basicConstraintsBuilder;

    private BasicConstraints basicConstraints;
    private Extension basicConstraintsActual;

    private boolean isCA = true;

    private static final boolean isCritical = true;

    /**
     * Prepares initial data.
     */
    @Before
    public void setUp() {
        basicConstraints = new BasicConstraints();
        basicConstraints.setIsCA(isCA);
        basicConstraints.setPathLenConstraint(4);
        basicConstraints.setCritical(isCritical);
    }

    /**
     * Method to test building of {@link BasicConstraints} extension for CAEntity.
     * 
     * @throws IOException
     */
    @Test
    public void testBuildBasicConstraintsForCA() throws IOException {
        basicConstraintsActual = basicConstraintsBuilder.buildBasicConstraints(basicConstraints);

        final DEROctetString basicConstraintsExpected = new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(basicConstraints.getPathLenConstraint()));

        assertExtensionValue(basicConstraintsExpected, basicConstraintsActual);
        assertEquals(Extension.basicConstraints, basicConstraintsActual.getExtnId());
    }

    /**
     * Method to test building of {@link BasicConstraints} extension for Entity.
     * 
     * @throws IOException
     */
    @Test
    public void testBuildBasicConstraintsForEE() throws IOException {
        isCA = false;
        basicConstraints.setIsCA(isCA);

        basicConstraintsActual = basicConstraintsBuilder.buildBasicConstraints(basicConstraints);

        final DEROctetString basicConstraintsExpected = new DEROctetString(new org.bouncycastle.asn1.x509.BasicConstraints(basicConstraints.isCA()));

        assertExtensionValue(basicConstraintsExpected, basicConstraintsActual);
        assertEquals(Extension.basicConstraints, basicConstraintsActual.getExtnId());
    }
}
