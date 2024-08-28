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
/**
 * @author tcsvenp
 *
 */
package com.ericsson.oss.itpf.security.pki.manager.model;

import static org.junit.Assert.assertNotEquals;

import java.lang.reflect.InvocationTargetException;
import java.text.ParseException;

import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CertificateChainSetUpData;

/**
 * This class is used to run Junits for CertificateChainTest objects in different scenarios
 */
public class CertificateChainTest extends EqualsTestCase {

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() throws ParseException {
        return new CertificateChainSetUpData().getCertificateChainDataForEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() throws ParseException {
        return new CertificateChainSetUpData().getCertificateChainDataForNotEqual();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEachFieldNull()
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws IllegalAccessException, IllegalArgumentException, InvocationTargetException, ParseException {
        final Object eq1 = createInstance();
        final Object tempObject1 = new CertificateChain();
        assertNotEquals(eq1, tempObject1);
        assertNotEquals(tempObject1, eq1);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEmptyList()
     */
    @Override
    @Test
    public void testWithEmptyList() throws Exception {
        final Object eq1 = createInstance();
        final Object tempObject1 = new CertificateChainSetUpData().getCertificateChainWithEmptyList();
        assertNotEquals(eq1, tempObject1);
        assertNotEquals(tempObject1, eq1);
    }

}
