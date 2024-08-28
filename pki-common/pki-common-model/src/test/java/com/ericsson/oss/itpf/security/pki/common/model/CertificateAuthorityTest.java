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
package com.ericsson.oss.itpf.security.pki.common.model;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.mockito.Mock;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.*;

/**
 * This class is used to run Junits for CertificateAuthority objects in different scenarios
 */
public class CertificateAuthorityTest extends EqualsTestCase {

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */

    @Mock
    private Logger logger;

    @Override
    public Object createInstance() throws ParseException {

        final List<Certificate> certificates = new ArrayList<Certificate>();
        final List<CRLInfo> crls = new ArrayList<CRLInfo>();
        final List<CrlGenerationInfo> crlGenerationInfoList=new ArrayList<CrlGenerationInfo>();
        crlGenerationInfoList.add(new CrlGenerationInfo());
        CRLInfo crl=new CRLInfo();
        crls.add(crl);
        certificates.add((new CertificateSetUpData()).getCertificateForEqual());

        return (new CertificateAuthoritySetUpData()).name(CommonConstants.CERT_AUTH_EQUAL_NAME).status(CAStatus.ACTIVE).subject((new SubjectSetUpData()).getSubjectForCreate()).crls(crls)
                .subjectAltName((new SubjectAltNameStringSetUpData().getSANForCreate())).activeCertificate(new CertificateSetUpData().getCertificateForEqual()).inActiveCertificates(certificates)
                .isRootCA(true).issuer(new CertificateAuthoritySetUpData().getIssuer()).crlGenerationInfo(crlGenerationInfoList).build();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    public Object createNotEqualInstance() throws ParseException {

        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add((new CertificateSetUpData()).getCertificateForNotEqual());

        return (new CertificateAuthoritySetUpData()).name(CommonConstants.CERT_AUTH_NOT_EQUAL_NAME).status(CAStatus.INACTIVE).subject((new SubjectSetUpData()).getSubjectForCreateNotEqual())
                .subjectAltName((new SubjectAltNameStringSetUpData()).getSANForCreateNotEqual()).activeCertificate(new CertificateSetUpData().getCertificateForNotEqual())
                .inActiveCertificates(certificates).issuer(new CertificateAuthoritySetUpData().getIssuer()).build();
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
        final Class tClass = eq1.getClass();
        final Object nullObject = null;
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(CommonConstants.SET)) {
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

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#testWithEmptyList()
     */
    @Override
    @Test
    public void testWithEmptyList() throws Exception {
        final Object eq1 = createInstance();
        final Class tClass = eq1.getClass();
        final Method[] methods = tClass.getMethods();
        Object tempObject1 = createInstance();
        Object tempObject2 = createInstance();
        for (final Method method : methods) {
            if (method.getName().startsWith(CommonConstants.SET)) {
                if (method.getParameterTypes()[0].getName().contains(CommonConstants.LIST) && !method.getParameterTypes()[0].isEnum()
                        && (!method.getName().equals(CommonConstants.SET_ACTIVE_KEY_PAIR) && !method.getName().equals(CommonConstants.SET_INACTIVE_KEY_PAIR))) {

                    Object getterMethodvalue = null;
                    Object newSetterMethodvalue = null;
                    try {
                        final Method getterMethod = tClass.getMethod(method.getName().replaceFirst("s", "g"));
                        getterMethodvalue = getterMethod.invoke(tempObject2);
                    } catch (final Exception exception) {
                        logger.debug("Exception occured here is ", exception);
                        continue;
                    }
                    if (getterMethodvalue != null) {
                        newSetterMethodvalue = new ArrayList();
                    }
                    method.invoke(tempObject2, newSetterMethodvalue);
                    method.invoke(tempObject1, newSetterMethodvalue);
                   assertNotEquals(eq1, tempObject1);
                   assertNotEquals(tempObject2, eq1);
                    assertEquals(tempObject1, tempObject2);
                    tempObject1 = createInstance();
                    tempObject2 = createInstance();
                }
            }
        }
    }

}
