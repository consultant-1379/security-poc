/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;

@RunWith(MockitoJUnitRunner.class)
public class CRLInfoDataTest extends EqualsTestCase {
    @InjectMocks
    CRLInfoData crlInfoData;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CRLInfoData createInstance() throws Exception {
        return getCRLInfoData();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CRLInfoData createNotEqualInstance() throws Exception {
        return getCRLInfoDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CRLData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CRLInfoData crlInfoData = createInstance();
        final Class<? extends Object> crlInfoDataClass = crlInfoData.getClass();
        final Object nullObject = null;
        final Method[] methods = crlInfoDataClass.getMethods();
        Object tempObject1 = null;
        Object tempObject2 = null;
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()
                        && !method.getParameterTypes()[0].isInterface()) {

                    tempObject1 = createNotEqualInstance();
                    tempObject2 = createNotEqualInstance();

                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);

                    assertNotEquals(crlInfoData, tempObject1);
                    assertNotEquals(tempObject1, crlInfoData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    private CRLInfoData getCRLInfoData() {
        final CRLInfoData crlInfoData = new CRLInfoData();
        crlInfoData.setId(3);

        final CRLData crlData = new CRLData();
        crlData.setCrl("crl".getBytes());
        crlData.setId(3);

        crlInfoData.setCrl(crlData);
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1);

        crlInfoData.setCertificateData(certificateData);
        crlInfoData.setCreatedDate(new Date("1/12/2015"));
        crlInfoData.setCrlnumber(1235);
        crlInfoData.setModifiedDate(new Date("1/2/2016"));
        crlInfoData.setNextUpdate(new Date("1/12/2017"));
        crlInfoData.setPublishedTocdps(true);
        crlInfoData.setStatus(1);
        crlInfoData.setThisUpdate(new Date("1/12/2016"));

        return crlInfoData;
    }

    private CRLInfoData getCRLInfoDataNotEqual() {
        final CRLInfoData crlInfoData = new CRLInfoData();
        crlInfoData.setId(9);

        final CRLData crlData = new CRLData();
        crlData.setCrl("crlTest".getBytes());
        crlData.setId(36);

        crlInfoData.setCrl(crlData);
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(10);

        crlInfoData.setCertificateData(certificateData);
        crlInfoData.setCreatedDate(new Date("1/10/2015"));
        crlInfoData.setCrlnumber(1235);
        crlInfoData.setModifiedDate(new Date("10/2/2016"));
        crlInfoData.setNextUpdate(new Date("1/10/2017"));
        crlInfoData.setPublishedTocdps(true);
        crlInfoData.setStatus(1);
        crlInfoData.setThisUpdate(new Date("10/12/2016"));

        return crlInfoData;
    }

    /**
     * This method tests getters,setters and toString methods of CRLInfoData class
     */
    @Test
    public void testMethods() throws Exception {
        crlInfoData = createInstance();
        crlInfoData.onCreate();
        crlInfoData.onUpdate();

        assertGetValues();
    }

    private void assertGetValues() {
        assertNotNull(crlInfoData.getId());
        assertNotNull(crlInfoData.getCertificateData());
        assertNotNull(crlInfoData.getCreatedDate());
        assertNotNull(crlInfoData.getCrl());
        assertNotNull(crlInfoData.getNextUpdate());
        assertNotNull(crlInfoData.getModifiedDate());
        assertNotNull(crlInfoData.getThisUpdate());
        assertNotNull(crlInfoData.getCrlnumber());
        assertNotNull(crlInfoData.getStatus());
        assertNotNull(crlInfoData.toString());
    }
}
