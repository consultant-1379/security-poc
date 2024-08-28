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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.entity;


import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.CertificateGenerationInfoSetUpData;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateGenerationInfoData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateGenerationInfoDataTest extends EqualsTestCase {

    @InjectMocks
    CertificateGenerationInfoData certificateGenerationInfoData;

    @Override
    protected Object createInstance() {
        return new CertificateGenerationInfoSetUpData().getCertificateGenerationInfoDataForEqual();
    }

    @Override
    protected Object createNotEqualInstance() {
        return new CertificateGenerationInfoSetUpData().getCertificateGenerationInfoDataForNotEqual();
    }

    /**
     * Method to test equals method of {@link CertificateGenerationInfoData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith("set")) {
                if (method.getParameterTypes()[0].getName().contains(".") && !method.getParameterTypes()[0].isEnum()) {
                    method.invoke(tempObject2, nullObject);
                    method.invoke(tempObject1, nullObject);
                    assertNotEquals(eq1, tempObject1);
                    assertNotEquals(tempObject1, eq1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }
    
    /**
     * Method to test getter method of {@link CertificateGenerationInfoData}
     */
    @Test
    public void testMethods() {
    	certificateGenerationInfoData = new CertificateGenerationInfoSetUpData().getCertificateGenerationInfoDataForEqual();
        assertNotNull(certificateGenerationInfoData.getId());
        assertNotNull(certificateGenerationInfoData.getcAEntityInfo());
        assertNotNull(certificateGenerationInfoData.getCertificateData());
        assertNotNull(certificateGenerationInfoData.getCertificateExtensionsJSONData());
        assertNotNull(certificateGenerationInfoData.getCertificateRequestData());
        assertNotNull(certificateGenerationInfoData.getCertificateVersion());
        assertNotNull(certificateGenerationInfoData.getClass());
        assertNotNull(certificateGenerationInfoData.getEntityInfo());
        assertNotNull(certificateGenerationInfoData.getIssuerCA());
        assertNotNull(certificateGenerationInfoData.getKeyGenerationAlgorithmData());
        assertNotNull(certificateGenerationInfoData.getRequestType());
        assertNotNull(certificateGenerationInfoData.getSignatureAlgorithmData());
        assertNotNull(certificateGenerationInfoData.getIssuerSignatureAlgorithmData());
        assertNotNull(certificateGenerationInfoData.getSkewCertificateTime());
        assertNotNull(certificateGenerationInfoData.getValidity());
        assertNotNull(certificateGenerationInfoData.toString());
        assertNotNull(certificateGenerationInfoData.getSubjectUniqueIdentifierValue());
        assertNotNull(certificateGenerationInfoData.isSubjectUniqueIdentifier());
    }
}
