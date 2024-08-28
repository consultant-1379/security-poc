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
import static org.junit.Assert.assertNull;

import java.lang.reflect.Method;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.AlgorithmDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.CAEntityDataSetUp;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateGenerationInfoDataTest extends EqualsTestCase {

    @InjectMocks
    CertificateGenerationInfoData certificateGenerationInfoData;

    AlgorithmDataSetUp algorithmDataSetUp = new AlgorithmDataSetUp();
    CAEntityDataSetUp caEntityDataSetUp = new CAEntityDataSetUp();
    EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CertificateGenerationInfoData createInstance() throws Exception {
        return createCertificateGenerationInfoData();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CertificateGenerationInfoData createNotEqualInstance() throws Exception {
        return createCertificateGenerationInfoDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CertificateGenerationInfoData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CertificateGenerationInfoData certificateGenerationInfoData = createInstance();
        final Class<? extends Object> certificateGenerationInfoDataClass = certificateGenerationInfoData.getClass();
        final Object nullObject = null;
        final Method[] methods = certificateGenerationInfoDataClass.getMethods();
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

                    assertNotEquals(certificateGenerationInfoData, tempObject1);
                    assertNotEquals(tempObject1, certificateGenerationInfoData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    private CertificateGenerationInfoData createCertificateGenerationInfoData() {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        certificateGenerationInfoData.setId(1);
        certificateGenerationInfoData.setCertificateVersion(CertificateVersion.V3);
        certificateGenerationInfoData.setSubjectUniqueIdentifier(true);
        certificateGenerationInfoData.setIssuerUniqueIdentifier(true);
        final CAEntityData caEntityData = caEntityDataSetUp.getCAEntity(1, "Test_CA1", true, entitiesSetUpData.getEntityProfileData(),
                entitiesSetUpData.getCertificateProfileDatas(), "CN=Test1", "DN=www.xyz.com");
        certificateGenerationInfoData.setcAEntityInfo(caEntityData);

        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1);
        certificateGenerationInfoData.setCertificateData(certificateData);
        certificateGenerationInfoData.setCertificateExtensionsJSONData("CertificateExtensionsJSONDataTests");

        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setId(2);
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        certificateGenerationInfoData.setEntityInfo(entitiesSetUpData.getEntityData());

        certificateGenerationInfoData.setIssuerCA(caEntityData);

        certificateGenerationInfoData.setKeyGenerationAlgorithmData(algorithmDataSetUp.getSupportedKeyGenerationAlgorithm());
        certificateGenerationInfoData.setRequestType(RequestType.MODIFY);
        certificateGenerationInfoData.setSignatureAlgorithmData(algorithmDataSetUp.getSupportedSignatureAlgorithm());
        certificateGenerationInfoData.setSkewCertificateTime("12345");
        certificateGenerationInfoData.setValidity("2y");
        return certificateGenerationInfoData;

    }

    private CertificateGenerationInfoData createCertificateGenerationInfoDataNotEqual() {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        certificateGenerationInfoData.setId(7);
        certificateGenerationInfoData.setCertificateVersion(null);
        certificateGenerationInfoData.setSubjectUniqueIdentifier(false);
        certificateGenerationInfoData.setIssuerUniqueIdentifier(false);

        certificateGenerationInfoData.setcAEntityInfo(null);

        final CertificateData certificateData = new CertificateData();
        certificateData.setId(2);
        certificateGenerationInfoData.setCertificateData(certificateData);
        certificateGenerationInfoData.setCertificateExtensionsJSONData("CertificateExtensionsJSONData");

        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setId(2);
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        certificateGenerationInfoData.setEntityInfo(null);

        certificateGenerationInfoData.setIssuerCA(null);

        certificateGenerationInfoData.setKeyGenerationAlgorithmData(algorithmDataSetUp.getSupportedSignatureAlgorithm());
        certificateGenerationInfoData.setRequestType(RequestType.RENEW);
        certificateGenerationInfoData.setSignatureAlgorithmData(algorithmDataSetUp.getSupportedKeyGenerationAlgorithm());
        certificateGenerationInfoData.setSkewCertificateTime("1234567");
        certificateGenerationInfoData.setValidity("3y");

        return certificateGenerationInfoData;

    }

    /**
     * This method tests getters,setters and toString methods of CertificateGenerationInfoData class
     */
    @Test
    public void testMethods() {
        certificateGenerationInfoData = createCertificateGenerationInfoData();
        assertNotNull(certificateGenerationInfoData.getRequestType());
        certificateGenerationInfoData.setRequestType(null);
        assertGetValues();
    }

    private void assertGetValues() {
        assertNotNull(certificateGenerationInfoData.getSkewCertificateTime());
        assertNotNull(certificateGenerationInfoData.getValidity());
        assertNotNull(certificateGenerationInfoData.getKeyGenerationAlgorithmData());
        assertNotNull(certificateGenerationInfoData.getSignatureAlgorithmData());
        assertNotNull(certificateGenerationInfoData.getCertificateExtensionsJSONData());
        assertNotNull(certificateGenerationInfoData.getCertificateData());
        assertNotNull(certificateGenerationInfoData.getEntityInfo());
        assertNotNull(certificateGenerationInfoData.getIssuerCA());
        assertNotNull(certificateGenerationInfoData.getCertificateRequestData());
        assertNotNull(certificateGenerationInfoData.toString());
        assertNotNull(certificateGenerationInfoData.getcAEntityInfo());
        assertNotNull(certificateGenerationInfoData.getId());
        assertNotNull(certificateGenerationInfoData.getCertificateVersion());
        assertNull(certificateGenerationInfoData.getRequestType());

    }
}
