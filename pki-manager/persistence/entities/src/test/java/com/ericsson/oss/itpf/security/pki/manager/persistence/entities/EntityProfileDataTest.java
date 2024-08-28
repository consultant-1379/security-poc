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

import java.lang.reflect.Method;

import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;

/**
 * This class will test EntityData
 * 
 * @author tcsrav
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class EntityProfileDataTest extends EqualsTestCase {

    EntityProfileData entityProfileData;

    @Override
    public void testWithEachFieldNull() throws Exception {
        entityProfileData = createInstance();
        final Class<? extends Object> certificateDataClass = entityProfileData.getClass();
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

                    assertNotEquals(entityProfileData, tempObject1);
                    assertNotEquals(tempObject1, entityProfileData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    @Override
    public void testWithEachFieldChange() throws Exception {
        entityProfileData = createInstance();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase#createInstance()
     */
    @Override
    protected EntityProfileData createInstance() throws Exception {
        // TODO Auto-generated method stub
        return createEntityProfileDataEQ();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected EntityProfileData createNotEqualInstance() throws Exception {

        return createEntityProfileDataNotEQ();
    }

    public EntityProfileData createEntityProfileDataEQ() {

        EntityDataSetUp setUpData = new EntityDataSetUp();

        EntityProfileData entityProfileData = setUpData.createEntityProfileData();

        return entityProfileData;

    }

    public EntityProfileData createEntityProfileDataNotEQ() {

        EntityDataSetUp setUpData = new EntityDataSetUp();
        EntityProfileData entityProfileData = setUpData.createEntityProfileData();
        entityProfileData.setId(10);
        entityProfileData.setName("ENMRtCAEntityProfile");
        entityProfileData.setSubjectDN("O=Tcs");
        entityProfileData.setSubjectAltName("Test");
        entityProfileData.setKeyGenerationAlgorithm(setUpData.createKeyGenerationAlgorithmData(5, "SHA", 4098));

        entityProfileData.setModifiable(false);

        final CertificateProfileData certificateProfileData = new CertificateProfileData();

        certificateProfileData.setId(10);
        certificateProfileData.setName("EdgdfNMRootCACertificateProfile");
        certificateProfileData.setForCAEntity(false);

        entityProfileData.setCertificateProfileData(certificateProfileData);

        return entityProfileData;

    }

}
