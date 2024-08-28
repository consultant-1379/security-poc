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

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;

@RunWith(MockitoJUnitRunner.class)
public class CertificateDataTest extends EqualsTestCase {
    @InjectMocks
    CertificateData certificateData;

    private Date currentIssueTime = new Date();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CertificateData createInstance() throws Exception {
        return createCertificateData();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CertificateData createNotEqualInstance() throws Exception {
        return createCertificateDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CertificateData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CertificateData certificateData = createInstance();
        final Class<? extends Object> certificateDataClass = certificateData.getClass();
        final Object nullObject = null;
        final Method[] methods = certificateDataClass.getMethods();
        Object tempObject1 = null;
        Object tempObject2 = null;
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum() && !method.getParameterTypes()[0].isInterface()) {

                    tempObject1 = createNotEqualInstance();
                    tempObject2 = createNotEqualInstance();

                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);

                    assertNotEquals(certificateData, tempObject1);
                    assertNotEquals(tempObject1, certificateData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    /**
     * This method tests getters,setters and toString methods of CertificateData class
     */
    @Test
    public void testMethods() {
        certificateData.onCreate();
        certificateData.onUpdate();
        assertNotNull(certificateData.getCreatedDate());
        assertNotNull(certificateData.getModifiedDate());
        assertNotNull(certificateData.toString());
    }

    private CertificateData createCertificateData() throws CertificateEncodingException, CertificateException, IOException {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1);
        certificateData.setNotBefore(new Date("10/03/2016"));
        certificateData.setNotAfter(new Date("10/03/2016"));
        certificateData.setIssuedTime(currentIssueTime);
        certificateData.setSerialNumber("SN12233695");
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());
        return certificateData;

    }

    private CertificateData createCertificateDataNotEqual() throws CertificateEncodingException, CertificateException, IOException {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(2);
        certificateData.setNotBefore(new Date("10/03/2016"));
        certificateData.setNotAfter(new Date("10/03/2016"));
        certificateData.setIssuedTime(new Date("10/03/2016"));
        certificateData.setSerialNumber("SN122336957676");
        certificateData.setStatus(CertificateStatus.REVOKED.getId());
        certificateData.setCertificate(null);
        return certificateData;

    }

}