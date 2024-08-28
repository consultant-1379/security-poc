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

import java.io.IOException;
import java.lang.reflect.Method;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.persistence.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.CrlGenerationInfoSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.common.data.EntitiesSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateAuthorityDataTest extends EqualsTestCase {
    @InjectMocks
    CertificateAuthorityData certificateAuthorityData;

    public final static String SUBJECT_STRING = "CN=ENM_Root";
    EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
    CrlGenerationInfoSetUpData crlGenerationInfoSetUpData = new CrlGenerationInfoSetUpData();

    public final static String SUBJECT_ALT_NAME_JSON = "{\"@class\":\".SubjectAltName\",\"critical\":false,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"www.xyz.com\"}}]}";
    public final static String SUBJECT_ALT_NAME_JSON_OTHER = "{\"@class\":\".SubjectAltName\",\"critical\":true,\"subjectAltNameFields\":[{\"type\":\"DIRECTORY_NAME\",\"value\":{\"@class\":\".SubjectAltNameString\",\"value\":\"www.abc.com\"}}]}";
    private Date currentTime = new Date();

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected CertificateAuthorityData createInstance() throws Exception {
        return createCertificateAuthorityData();
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected CertificateAuthorityData createNotEqualInstance() throws Exception {
        return createCertificateAuthorityDataNotEqual();
    }

    /**
     * Method to test equals method of {@link CertificateAuthorityData}
     */
    @Override
    @Test
    public void testWithEachFieldNull() throws Exception {
        final CertificateAuthorityData certificateAuthorityData = createInstance();
        final Class<? extends Object> certificateAuthorityDataClass = certificateAuthorityData.getClass();
        final Object nullObject = null;
        final Method[] methods = certificateAuthorityDataClass.getMethods();
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

                    assertNotEquals(certificateAuthorityData, tempObject1);
                    assertNotEquals(tempObject1, certificateAuthorityData);
                    assertEquals(tempObject1, tempObject2);
                }
            }
        }
    }

    private CertificateAuthorityData createCertificateAuthorityData() throws CertificateEncodingException, CertificateException, IOException {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setName("ENMRootCA1");
        certificateAuthorityData.setSubjectDN("CN=ENM_Root_1");
        certificateAuthorityData.setSubjectAltName(SUBJECT_ALT_NAME_JSON);
        certificateAuthorityData.setIssuer(null);
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setStatus(CAStatus.NEW.getId());
        certificateAuthorityData.setCreatedDate(new Date("02/09/2004"));

        final Set<CRLInfoData> cRLDatas = new HashSet<CRLInfoData>();
        final CRLInfoData crlInfoDataExpire = new CRLInfoData();
        crlInfoDataExpire.setNextUpdate(new Date("02/09/2016"));
        cRLDatas.add(crlInfoDataExpire);
        certificateAuthorityData.setcRLDatas(cRLDatas);

        final Set<CrlGenerationInfoData> crlGenerationInfo = new HashSet<CrlGenerationInfoData>();
        crlGenerationInfo.add(crlGenerationInfoSetUpData.getCrlGenerationInfoData());
        certificateAuthorityData.setCrlGenerationInfo(crlGenerationInfo);

        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setId(12);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        certificateAuthorityData.setModifiedDate(new Date("02/10/2016"));
        certificateAuthorityData.setPublishToCDPS(true);

        return certificateAuthorityData;
    }

    private CertificateAuthorityData createCertificateAuthorityDataNotEqual() {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setName("ENMRootCA");
        certificateAuthorityData.setSubjectDN("CN=ENM_Root_2");
        certificateAuthorityData.setSubjectAltName(SUBJECT_ALT_NAME_JSON_OTHER);
        certificateAuthorityData.setIssuer(entitiesSetUpData.getCaEntityData());
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE.getId());

        certificateAuthorityData.setCreatedDate(new Date("02/09/2015"));

        final Set<CRLInfoData> cRLDatas = new HashSet<CRLInfoData>();
        final CRLInfoData crlInfoDataExpire = new CRLInfoData();
        crlInfoDataExpire.setNextUpdate(new Date("05/09/2016"));
        cRLDatas.add(crlInfoDataExpire);
        certificateAuthorityData.setcRLDatas(cRLDatas);

        final Set<CrlGenerationInfoData> crlGenerationInfo = new HashSet<CrlGenerationInfoData>();
        certificateAuthorityData.setCrlGenerationInfo(crlGenerationInfo);

        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setId(19);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        certificateAuthorityData.setModifiedDate(new Date("02/11/2016"));
        certificateAuthorityData.setPublishToCDPS(true);

        return certificateAuthorityData;
    }

    /**
     * This method tests getters,setters and toString methods of CertificateAuthorityData class
     */
    @Test
    public void testMethods() throws CertificateEncodingException, CertificateException, IOException {
        certificateAuthorityData.setCreatedDate(currentTime);
        certificateAuthorityData.setModifiedDate(currentTime);
        certificateAuthorityData.setStatus(new Integer(1));
        certificateAuthorityData.setName("test");
        certificateAuthorityData.setSubjectAltName("SubjectAltName");
        certificateAuthorityData.setSubjectDN("subjectDN");
        certificateAuthorityData.setIssuer(entitiesSetUpData.getCaEntityData());
        certificateAuthorityData.setCertificateDatas(crlGenerationInfoSetUpData.getCrlCertificateDataSet());

        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setId(1);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);

        final Set<CrlGenerationInfoData> crlGenerationInfo = new HashSet<CrlGenerationInfoData>();
        crlGenerationInfo.add(crlGenerationInfoSetUpData.getCrlGenerationInfoData());
        certificateAuthorityData.setCrlGenerationInfo(crlGenerationInfo);

        final Set<CRLInfoData> crlInfoDatas = new HashSet<CRLInfoData>();
        final CRLInfoData crlInfoData = new CRLInfoData();
        crlInfoData.setId(1);
        crlInfoDatas.add(crlInfoData);

        certificateAuthorityData.setcRLDatas(crlInfoDatas);

        certificateAuthorityData.equals(certificateAuthorityData);

        assertGetValues();
    }

    private void assertGetValues() {
        assertNotNull(certificateAuthorityData.toString());
        assertNotNull(certificateAuthorityData.getCreatedDate());
        assertNotNull(certificateAuthorityData.getModifiedDate());
        assertNotNull(certificateAuthorityData.getStatus());
        assertNotNull(certificateAuthorityData.getName());
        assertNotNull(certificateAuthorityData.getSubjectAltName());
        assertNotNull(certificateAuthorityData.getSubjectDN());
        assertNotNull(certificateAuthorityData.getIssuer());
        assertNotNull(certificateAuthorityData.getCertificateDatas());
        assertNotNull(certificateAuthorityData.getExternalCrlInfoData());
        assertNotNull(certificateAuthorityData.getCrlGenerationInfo());
        assertNotNull(certificateAuthorityData.getcRLDatas());
    }
}