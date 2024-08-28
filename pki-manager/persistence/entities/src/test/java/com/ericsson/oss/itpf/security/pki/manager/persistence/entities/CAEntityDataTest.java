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
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.AlgorithmDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.CAEntityDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityDataTest extends EqualsTestCase {
    @InjectMocks
    CAEntityData caEntityData;

    CAEntityDataSetUp caEntityDataSetUp = new CAEntityDataSetUp();
    EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
    AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CAEntityData createInstance() throws Exception {
        return caEntityDataSetUp.getCAEntity(1, "Test_CA1", true, entitiesSetUpData.getEntityProfileData(),
                entitiesSetUpData.getCertificateProfileDatas(), "CN=Test1", "DN=www.xyz.com");
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CAEntityData createNotEqualInstance() throws Exception {
        return caEntityDataSetUp.getCAEntity(2, "Test_CA2", false, new EntityProfileData(), new HashSet<CertificateProfileData>(), "CN=Test2",
                "DN=www.qwerty.com");
    }

    /**
     * Method to test equals method of {@link CAEntityData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CAEntityData caEntityData = createInstance();
        final Class<? extends Object> caEntityDataClass = caEntityData.getClass();
        final Object nullObject = null;
        final Method[] methods = caEntityDataClass.getMethods();
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

                    assertNotEquals(caEntityData, tempObject1);
                    assertNotEquals(tempObject1, caEntityData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    /**
     * This method tests getters,setters and toString methods of CAEntityData class
     */
    @Test
    public void testMethods() {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setStatus(1);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.onCreate();
        caEntityData.onUpdate();

        final CAEntityData caentitydata = new CAEntityData();
        caentitydata.setId(1);
        final Set<CAEntityData> caEntityDataSet = new HashSet<CAEntityData>();
        caEntityDataSet.add(caentitydata);
        caEntityData.setAssociated(caEntityDataSet);
        caEntityData.setId(1);
        caEntityData.setKeyGenerationAlgorithm(algorithmDataSetUp.getSupportedKeyGenerationAlgorithm());
        caEntityData.setCertificateProfiles(entitiesSetUpData.getCertificateProfileDatas());
        caEntityData.setCertificateExpiryNotificationDetailsData(caEntityData.getCertificateExpiryNotificationDetailsData());
        assertGetValues();
    }

    private void assertGetValues() {
        assertNotNull(caEntityData.getAssociated());
        assertNotNull(caEntityData.getId());
        assertNotNull(caEntityData.getCertificateAuthorityData());
        assertNotNull(caEntityData.getKeyGenerationAlgorithm());
        assertNotNull(caEntityData.getCertificateProfiles());
        assertNotNull(caEntityData.toString());

    }
}