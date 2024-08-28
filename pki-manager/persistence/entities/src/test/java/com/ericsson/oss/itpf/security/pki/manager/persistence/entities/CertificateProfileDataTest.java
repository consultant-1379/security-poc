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

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.AlgorithmDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.CAEntityDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileDataTest extends EqualsTestCase {

    @InjectMocks
    CertificateProfileData certificateProfileData;

    AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();
    CAEntityDataSetUp caEntityDataSetUp = new CAEntityDataSetUp();
    EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CertificateProfileData createInstance() throws Exception {
        return getCertificateProfileData();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CertificateProfileData createNotEqualInstance() throws Exception {
        return getCertificateProfileDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CertificateProfileData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CertificateProfileData certificateProfileData = createInstance();
        final Class<? extends Object> certificateProfileDataDataClass = certificateProfileData.getClass();
        final Object nullObject = null;
        final Method[] methods = certificateProfileDataDataClass.getMethods();
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

                    assertNotEquals(certificateProfileData, tempObject1);
                    assertNotEquals(tempObject1, certificateProfileData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    private CertificateProfileData getCertificateProfileData() {

        final CertificateProfileData certificateProfileData = new CertificateProfileData();

        certificateProfileData.setId(1);
        certificateProfileData.setName("ENMRootCACertificateProfile");
        certificateProfileData.setForCAEntity(true);
        certificateProfileData.setActive(true);
        certificateProfileData.setCertificateExtensionsJSONData("certificateExtensionsJSONData");
        certificateProfileData.setCreatedDate(new Date("10/22/2015"));

        final CAEntityData caEntityData = caEntityDataSetUp.getCAEntity(1, "Test_CA1", true, entitiesSetUpData.getEntityProfileData(),
                entitiesSetUpData.getCertificateProfileDatas(), "CN=Test1", "DN=www.xyz.com");

        certificateProfileData.setIssuerData(caEntityData);
        certificateProfileData.setIssuerUniqueIdentifier(true);
        certificateProfileData.setKeyGenerationAlgorithms(algorithmDataSetUp.getKeyGenerationAlgorithmList());
        certificateProfileData.setModifiable(true);
        certificateProfileData.setModifiedDate(new Date("1/22/2016"));
        certificateProfileData.setProfileValidity(new Date("1/22/2017"));
        certificateProfileData.setSignatureAlgorithm(algorithmDataSetUp.getSupportedSignatureAlgorithm());
        certificateProfileData.setSkewCertificateTime("1stJan");
        certificateProfileData.setSubjectCapabilities("subjectCapabilities");
        certificateProfileData.setSubjectUniqueIdentifier(true);
        certificateProfileData.setValidity("P2Y");
        certificateProfileData.setVersion(CertificateVersion.V3);

        return certificateProfileData;

    }

    private CertificateProfileData getCertificateProfileDataNotEqual() {

        final CertificateProfileData certificateProfileData = new CertificateProfileData();

        certificateProfileData.setId(2);
        certificateProfileData.setName("ENMRootCACertificateProfileTest");
        certificateProfileData.setForCAEntity(false);
        certificateProfileData.setActive(true);
        certificateProfileData.setCertificateExtensionsJSONData("certificateExtensionsJSONDataTest");
        certificateProfileData.setCreatedDate(new Date("1/22/2016"));
        certificateProfileData.setIssuerData(null);
        certificateProfileData.setIssuerUniqueIdentifier(false);
        certificateProfileData.setKeyGenerationAlgorithms(null);
        certificateProfileData.setModifiable(false);
        certificateProfileData.setModifiedDate(new Date("2/22/2016"));
        certificateProfileData.setProfileValidity(new Date("1/22/2018"));
        certificateProfileData.setSignatureAlgorithm(null);
        certificateProfileData.setSkewCertificateTime("1stFeb");
        certificateProfileData.setSubjectCapabilities("subjectCapabilitiesTest");
        certificateProfileData.setSubjectUniqueIdentifier(false);
        certificateProfileData.setValidity("P3Y");
        certificateProfileData.setVersion(null);

        return certificateProfileData;

    }

    /**
     * This method tests getters,setters and toString methods of CertificateProfileData class
     */
    @Test
    public void testMethods() throws Exception {
        certificateProfileData = createInstance();
        assertGetValues();
    }

    private void assertGetValues() {
        assertNotNull(certificateProfileData.getCertificateExtensionsJSONData());
        assertNotNull(certificateProfileData.getKeyGenerationAlgorithms());
        assertNotNull(certificateProfileData.getValidity());
        assertNotNull(certificateProfileData.getVersion());
        assertNotNull(certificateProfileData.getSkewCertificateTime());
        assertNotNull(certificateProfileData.getSubjectCapabilities());
        assertNotNull(certificateProfileData.getIssuerData());
        assertNotNull(certificateProfileData.getSignatureAlgorithm());

        assertNotNull(certificateProfileData.toString());
    }
}
