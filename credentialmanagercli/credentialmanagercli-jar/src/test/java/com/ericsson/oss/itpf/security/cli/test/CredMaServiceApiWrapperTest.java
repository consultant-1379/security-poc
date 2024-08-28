/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerCertificateExtImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerKeyStoreImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerSubjectAlternateNameImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.KeyStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaExternalServiceApiWrapperFactory;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaExternalServiceApiWrapperImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperFactory;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperMock;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.CheckResult;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmsapi.api.InternalIfCredentialManagement;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.AlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetEndEntitiesByCategoryException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCategoryNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.InvalidCertificateFormatException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReIssueLegacyXMLCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ReissueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeEntityCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CertificateStatus;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.EntityType;
import com.ericsson.oss.itpf.security.credmsapi.api.model.KeystoreInfo;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustFormat;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustSource;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustStoreInfo;

@RunWith(MockitoJUnitRunner.class)
public class CredMaServiceApiWrapperTest {
    
    @InjectMocks
    CredMaServiceApiWrapperImpl mockWrapper;

    @Mock
    static InternalIfCredentialManagement mockIntIfc;
    
    @Test
    public void testConvertKeyFormat() {
        
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl");
            obj = cls.newInstance();
            final Class[] cArgs = new Class[1];
            cArgs[0] = String.class;
            method = CredMaServiceApiWrapperImpl.class.getDeclaredMethod("convertKeyFormat", cArgs);
            method.setAccessible(true);
        } catch (final Exception e2) {
            e2.printStackTrace();
        }
        
        
        CertificateFormat result = null;
        try {
            result = (CertificateFormat) method.invoke(obj,StoreConstants.BASE64_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertKeyFormat BASE_64 ", result==CertificateFormat.BASE_64);
        try {
            result = (CertificateFormat) method.invoke(obj,StoreConstants.JCEKS_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertKeyFormat JCEKS ", result==CertificateFormat.JCEKS);
        try {
            result = (CertificateFormat) method.invoke(obj,StoreConstants.JKS_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertKeyFormat JKS ", result==CertificateFormat.JKS);
        try {
            result = (CertificateFormat) method.invoke(obj,StoreConstants.PKCS12_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertKeyFormat PKCS12 ", result==CertificateFormat.PKCS12);
        
        try {
            result = (CertificateFormat) method.invoke(obj,"fake_format");
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertKeyFormat fake ",result == null);
    }
    
    @Test
    public void testConvertTrustFormat() {
        
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl");
            obj = cls.newInstance();
            final Class[] cArgs = new Class[1];
            cArgs[0] = String.class;
            method = CredMaServiceApiWrapperImpl.class.getDeclaredMethod("convertTrustFormat", cArgs);
            method.setAccessible(true);
        } catch (final Exception e2) {
            
            e2.printStackTrace();
        }
        
        
        TrustFormat result = null;
        try {
            result = (TrustFormat) method.invoke(obj,StoreConstants.BASE64_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertTrustFormat BASE_64 ", result==TrustFormat.BASE_64);
        try {
            result = (TrustFormat) method.invoke(obj,StoreConstants.JCEKS_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertTrusFormat JCEKS ", result==TrustFormat.JCEKS);
        try {
            result = (TrustFormat) method.invoke(obj,StoreConstants.JKS_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertTrustFormat JKS ", result==TrustFormat.JKS);
        try {
            result = (TrustFormat) method.invoke(obj,StoreConstants.PKCS12_STORE_TYPE);
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertTrustFormat PKCS12 ", result==TrustFormat.PKCS12);
        try {
            result = (TrustFormat) method.invoke(obj,"fakeFormat");
        } catch (final IllegalAccessException e) {
            
            e.printStackTrace();
        } catch (final IllegalArgumentException e) {
            
            e.printStackTrace();
        } catch (final InvocationTargetException e) {
            
            e.printStackTrace();
        }
        assertTrue("convertTrustFormat fake ",result == null);
    }  
    
    @Test
    public void testBuildSubjectAltName () {
        
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl");
            obj = cls.newInstance();
            final Class[] cArgs = new Class[1];
            cArgs[0] = CredentialManagerSubjectAltName.class;
            method = CredMaServiceApiWrapperImpl.class.getDeclaredMethod("buildSubjectAltName", cArgs);
            method.setAccessible(true);
        } catch (final Exception e2) {
            
            e2.printStackTrace();
        }
        
        com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType result = null;
        
        SubjectAlternativeNameType alt = new SubjectAlternativeNameType();
        alt.getIpaddress().add(0, "1.1.1.1");
        CredentialManagerSubjectAltName altName = new CredentialManagerSubjectAlternateNameImpl(alt);
        try {
            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue("buildSubjectAltName IP ", result.getIpaddress().get(0).equals("1.1.1.1"));
        
        alt = new SubjectAlternativeNameType();
        alt.getDirectoryname().add("DN=HOST_NAME");
        altName = new CredentialManagerSubjectAlternateNameImpl(alt);
        try {
            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue("buildSubjectAltName DIR ", result.getDirectoryname().get(0).equals("DN=HOST_NAME"));
 
        alt = new SubjectAlternativeNameType();
        alt.getDns().add("dns");
        altName = new CredentialManagerSubjectAlternateNameImpl(alt);
        try {
            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue("buildSubjectAltName DNS ", result.getDns().get(0).equals("dns"));
        
        alt = new SubjectAlternativeNameType();
        alt.getEmail().add("NAME@ericsson.com");
        altName = new CredentialManagerSubjectAlternateNameImpl(alt);
        try {
            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue("buildSubjectAltName EMAIL ", result.getEmail().get(0).equals("NAME@ericsson.com"));
        
//        alt = new SubjectAlternativeNameType();
//        alt.getOthername().add("othername");
//        altName = new CredentialManagerSubjectAlternateNameImpl(alt);
//        try {
//            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
//        } catch (final Exception e) {
//            
//            e.printStackTrace();
//        }
//        assertTrue("buildSubjectAltName OTHER ", result.getOthername().get(0).equals("othername"));
        
//        alt = new SubjectAlternativeNameType();
//        alt.getRegisteredid().add("registerid");
//        altName = new CredentialManagerSubjectAlternateNameImpl(alt);
//        try {
//            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
//        } catch (final Exception e) {
//            
//            e.printStackTrace();
//        }
//        assertTrue("buildSubjectAltName REG ", result.getRegisteredid().get(0).equals("registerid"));
        
        alt = new SubjectAlternativeNameType();
        alt.getUri().add("uri");
        altName = new CredentialManagerSubjectAlternateNameImpl(alt);
        try {
            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue("buildSubjectAltName URI ", result.getUri().get(0).equals("uri"));
        
        //nullpointer test
        CredentialManagerSubjectAltName altName2 = null;
        try {
            result = (com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType) method.invoke(obj,altName2);
            assertTrue(false);
        } catch (final CredentialManagerException e) {
            assertTrue(true);
        } catch (Exception e) {
            //error in mocking framework
        }
    }
    
    @Test
    public void convertTrustFormatTest() {
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl");
            obj = cls.newInstance();
            final Class[] cArgs = new Class[1];
            cArgs[0] = String.class;
            method = CredMaServiceApiWrapperImpl.class.getDeclaredMethod("convertTrustFormat", cArgs);
            method.setAccessible(true);
        } catch (final Exception e2) {
            e2.printStackTrace();
        }
        
        TrustFormat result = null;
        String format = StoreConstants.BASE64_STORE_TYPE;
        
        try {
            result = (TrustFormat) method.invoke(obj,format);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustFormat.BASE_64);
        
        format = StoreConstants.JCEKS_STORE_TYPE;
        
        try {
            result = (TrustFormat) method.invoke(obj,format);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustFormat.JCEKS);
        
        format = StoreConstants.JKS_STORE_TYPE;
        
        try {
            result = (TrustFormat) method.invoke(obj,format);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustFormat.JKS);
        
        format = StoreConstants.PKCS12_STORE_TYPE;
        
        try {
            result = (TrustFormat) method.invoke(obj,format);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustFormat.PKCS12);
        
        format = null;
        result = null;
        try {
            result = (TrustFormat) method.invoke(obj,format);
            assertTrue(false);
        } catch (final Exception e) {
            
            assertTrue(true);
        }
        assertTrue(result == null);
    }
    
    @Test
    public void testTrustSourceConvert() {
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl");
            obj = cls.newInstance();
            final Class[] cArgs = new Class[1];
            cArgs[0] = String.class;
            method = CredMaServiceApiWrapperImpl.class.getDeclaredMethod("convertTrustSource", cArgs);
            method.setAccessible(true);
        } catch (final Exception e2) {
            e2.printStackTrace();
        }
        
        TrustSource result = null;
        String source = SourceConstants.TRUST_SOURCE_INTERNAL;
        
        try {
            result = (TrustSource) method.invoke(obj,source);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustSource.INTERNAL);
        
        source = SourceConstants.TRUST_SOURCE_EXTERNAL;
        
        try {
            result = (TrustSource) method.invoke(obj,source);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustSource.EXTERNAL);
        
        source = SourceConstants.TRUST_SOURCE_BOTH;
        
        try {
            result = (TrustSource) method.invoke(obj,source);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == TrustSource.BOTH);
        
        source = "fake";
        result = null;
        try {
            result = (TrustSource) method.invoke(obj,source);
        } catch (final Exception e) {
            
            e.printStackTrace();
        }
        assertTrue(result == null);
    }
    
    @Test
    public void testbuildKeystoreInfoFail() throws IllegalArgumentException, InvocationTargetException {
        Class cls;
        Method method = null;
        Object obj = null;
        try {
            cls = Class.forName("com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl");
            obj = cls.newInstance();
            final Class[] cArgs = new Class[1];
            cArgs[0] = CredentialManagerKeyStore.class;
            method = CredMaServiceApiWrapperImpl.class.getDeclaredMethod("buildKeystoreInfo", cArgs);
            method.setAccessible(true);
        } catch (final Exception e2) {
            e2.printStackTrace();
        }
        
        KeystoreInfo result = null;
        CredentialManagerKeyStore source = null; //new CredentialManagerKeyStoreImpl(new KeyStoreType());
        
        try {
            result = (KeystoreInfo) method.invoke(obj,source);
            assertTrue(false);
        } catch (final Exception e) {
           assertTrue(result == null);
        }
        
    }
        
    //Check on null keystoreInfoList and TrustStoreInfoList
    @Test
    public void manageInfoListsNull() {
        final CredMaServiceApiWrapperImpl wrapper = new CredMaServiceApiWrapperImpl();
        
        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType(); 
        subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAltName credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);
        try {
            wrapper.manageCertificateAndTrust("entityName", "dnname", credMsubjAltName , "entityProfileName", null, null, null, null, false, false);
            assertTrue(false);
        } catch (final CredentialManagerException e) {
            assertTrue(true);
        }
        
        try {
            wrapper.manageCertificateAndTrust("entityName", "dnname", credMsubjAltName , "entityProfileName", new ArrayList<CredentialManagerKeyStore>(), null, null, null, false, false);
            assertTrue(false);
        } catch (final CredentialManagerException e) {
            assertTrue(true);
        }
    }
    
    @Test
    public void testManageCheck() throws IssueCertificateException {
    
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API"); 
        
        final CredMaServiceApiWrapperImpl wrapper = new CredMaServiceApiWrapperImpl();
        final String entityName = "entityName";
        final String distinguishName = "CN=entityName";
        final SubjectAlternativeNameType subjectAltName = new SubjectAlternativeNameType(); 
        subjectAltName.getIpaddress().add(0, "1.1.1.1");
        final CredentialManagerSubjectAltName credMsubjAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltName);
        final String entityProfileName = "entityProfileName";
        final List<CredentialManagerKeyStore> keystoreInfoList = new ArrayList<CredentialManagerKeyStore>();
        final List<CredentialManagerTrustStore> truststoreInfoList = new ArrayList<CredentialManagerTrustStore>();
        final List<CredentialManagerTrustStore> crlstoreInfoList = new ArrayList<CredentialManagerTrustStore>();
        //CertificateExtensionType extType = new CertificateExtensionType();
        final CredentialManagerCertificateExt certificateExt = new CredentialManagerCertificateExtImpl(null);
        
        final boolean certificateChain = false;
        final boolean firstDayRun = true;
        
        final CheckResult result = wrapper.manageCheck(entityName, distinguishName, credMsubjAltName, entityProfileName, 
                keystoreInfoList, truststoreInfoList, crlstoreInfoList, certificateExt, certificateChain, firstDayRun);

        assertTrue("manageCheck", result != null);
        
        CheckResult result2 = null;
        try {
            result2 = wrapper.manageCheck(entityName, distinguishName, credMsubjAltName, entityProfileName, 
                null, truststoreInfoList, crlstoreInfoList, certificateExt, certificateChain, firstDayRun);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(true);
            assertTrue(result2 == null);
        }
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.any(com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType.class), 
                Matchers.anyString(), Matchers.anyListOf(KeystoreInfo.class), Matchers.any(CredentialManagerCertificateExtension.class),
                Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(true);
        
        Mockito.when(mockIntIfc.checkAndUpdateTrusts(Matchers.anyString(), Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenReturn(true);

        Mockito.when(mockIntIfc.checkAndUpdateCRL(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenReturn(true);
        
        final CheckResult result3 = mockWrapper.manageCheck(entityName, distinguishName, credMsubjAltName, entityProfileName, 
                keystoreInfoList, truststoreInfoList, crlstoreInfoList, certificateExt, certificateChain, firstDayRun);

        assertTrue("manageCheck3", result3 != null);
                
    } 
    
    
    @Test
    public void manageCheckTrustAndCRL() throws IssueCertificateException {
        
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API"); 
        
        final CredMaServiceApiWrapperImpl wrapper = new CredMaServiceApiWrapperImpl();
        
        String trustProfileName = "pippoTP";
        List<CredentialManagerTrustStore> truststoreInfoList = new ArrayList<CredentialManagerTrustStore>();
        List<CredentialManagerTrustStore> crlstoreInfoList = new ArrayList<CredentialManagerTrustStore>();
        
        final CheckResult result = wrapper.manageCheckTrustAndCRL(trustProfileName, truststoreInfoList, crlstoreInfoList);
        assertTrue("manageCheckTrustCRLsTest", result != null);
        
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateTrustsTP(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class))).thenReturn(true);
        Mockito.when(mockIntIfc.checkAndUpdateCRL_TP(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenReturn(true);
        
        final CheckResult result2 = mockWrapper.manageCheckTrustAndCRL(trustProfileName, truststoreInfoList, crlstoreInfoList);
        assertTrue("manageCheckTrustCRLsTest2", result2 != null);

    }
    
    //TestFail manageCheck
    @Test
    public void testManageCheckCertFail() throws IssueCertificateException {
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.any(com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType.class), 
                Matchers.anyString(), Matchers.anyListOf(KeystoreInfo.class), Matchers.any(CredentialManagerCertificateExtension.class),
                Matchers.anyBoolean(), Matchers.anyBoolean())).thenThrow(new CredentialManagerException());
        CheckResult result = null;
        try {
                result = mockWrapper.manageCheck("entityName", "CN=entityName", new CredentialManagerSubjectAlternateNameImpl(new SubjectAlternativeNameType()), "entityProfileName", 
                        new ArrayList<CredentialManagerKeyStore>(), new ArrayList<CredentialManagerTrustStore>(), new ArrayList<CredentialManagerTrustStore>(), new CredentialManagerCertificateExtImpl(null),
                        false, true);
                assertTrue(false);
            } catch(CredentialManagerException e) {
                assertTrue(true);
                assertTrue(result == null);
            }
    }
    
    @Test
    public void testManageCheckTrustFail() throws IssueCertificateException {
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.any(com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType.class), 
                Matchers.anyString(), Matchers.anyListOf(KeystoreInfo.class), Matchers.any(CredentialManagerCertificateExtension.class),
                Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(true);
        Mockito.when(mockIntIfc.checkAndUpdateTrusts(Matchers.anyString(), Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenThrow(new CredentialManagerException());
        CheckResult result = null;
        
        try {
                result = mockWrapper.manageCheck("entityName", "CN=entityName", new CredentialManagerSubjectAlternateNameImpl(new SubjectAlternativeNameType()), "entityProfileName", 
                        new ArrayList<CredentialManagerKeyStore>(), new ArrayList<CredentialManagerTrustStore>(), new ArrayList<CredentialManagerTrustStore>(), new CredentialManagerCertificateExtImpl(null),
                        false, true);
                assertTrue(false);
            } catch(CredentialManagerException e) {
                assertTrue(true);
                assertTrue(result == null);
            }
    }
    
    @Test
    public void testManageCheckCRLFail() throws IssueCertificateException {
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateCertificate(Matchers.anyString(), Matchers.anyString(), Matchers.any(com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType.class), 
                Matchers.anyString(), Matchers.anyListOf(KeystoreInfo.class), Matchers.any(CredentialManagerCertificateExtension.class),
                Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(true);
        Mockito.when(mockIntIfc.checkAndUpdateTrusts(Matchers.anyString(), Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenReturn(true);
        Mockito.when(mockIntIfc.checkAndUpdateCRL(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenThrow(new CredentialManagerException());
        CheckResult result = null;
        
        try {
                result = mockWrapper.manageCheck("entityName", "CN=entityName", new CredentialManagerSubjectAlternateNameImpl(new SubjectAlternativeNameType()), "entityProfileName", 
                        new ArrayList<CredentialManagerKeyStore>(), new ArrayList<CredentialManagerTrustStore>(), new ArrayList<CredentialManagerTrustStore>(), new CredentialManagerCertificateExtImpl(null),
                        false, true);
                assertTrue(false);
            } catch(CredentialManagerException e) {
                assertTrue(true);
                assertTrue(result == null);
            }
    }
    
    //Test fails manageCheckTrustAndCRL
    
    @Test
    public void testManageCheckTrustAndCRL_TrustFail() throws IssueCertificateException{
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateTrustsTP(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class))).thenThrow(new CredentialManagerException());
        CheckResult result = null;
        try {
            result = mockWrapper.manageCheckTrustAndCRL("pippoTP", new ArrayList<CredentialManagerTrustStore>(), new ArrayList<CredentialManagerTrustStore>());
            assertTrue(false);
        } catch(CredentialManagerException e) {
            assertTrue(true);
            assertTrue(result == null);
        }
    }
    
    @Test
    public void testManageCheckTrustAndCRL_CRLFail() throws IssueCertificateException{
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "CREDMAN_SERVICE_API");
        
        Mockito.when(mockIntIfc.checkAndUpdateTrustsTP(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class))).thenReturn(true);
        Mockito.when(mockIntIfc.checkAndUpdateCRL_TP(Matchers.anyString(), Matchers.anyListOf(TrustStoreInfo.class), Matchers.anyBoolean())).thenThrow(new CredentialManagerException());
        CheckResult result = null;
        try {
            result = mockWrapper.manageCheckTrustAndCRL("pippoTP", new ArrayList<CredentialManagerTrustStore>(), new ArrayList<CredentialManagerTrustStore>());
            assertTrue(false);
        } catch(CredentialManagerException e) {
            assertTrue(true);
            assertTrue(result == null);
        }
    }
    
    @Test
    public void testCredMaExtWrapperFactory() throws IssueCertificateException, InvalidCertificateFormatException, CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException, GetEndEntitiesByCategoryException, InvalidCategoryNameException, ReissueCertificateException, RevokeCertificateException, OtpNotValidException, OtpExpiredException, ExpiredCertificateException, AlreadyRevokedCertificateException, RevokeEntityCertificateException, ReIssueLegacyXMLCertificateException {
        CredMaExternalServiceApiWrapperFactory wrappFactory = new CredMaExternalServiceApiWrapperFactory();
        CredMaExternalServiceApiWrapper extWrapp = null;
        try {
            extWrapp = wrappFactory.getInstance("FAKE_ENVIRONMENT");
            assertTrue(false);
        } catch(UnsupportedOperationException e) {
            assertTrue(extWrapp == null);
        }
        extWrapp = wrappFactory.getInstance("CREDMAN_SERVICE_API");
        assertTrue(extWrapp != null);
        CredMaExternalServiceApiWrapperImpl wrapp = (CredMaExternalServiceApiWrapperImpl) extWrapp;
        assertTrue(wrapp.getCredMaServiceApi() != null);
        assertTrue(!wrapp.getCredentialManagerInterfaceVersion().equals(""));
        try {
            wrapp.revokeCertificate(null, null);
            assertTrue(false);
        } catch (RevokeCertificateException e) {
            assertTrue(true);
        }
        KeystoreInfo ksInfo = new KeystoreInfo("/tmp/", null, null, null, CertificateFormat.JCEKS, "", "alias");
        EntityInfo eInfo = new EntityInfo();
        try {
            wrapp.reIssueCertificate(eInfo, ksInfo, null);
            assertTrue(false);
        } catch(ReissueCertificateException e) {
            assertTrue(true);
        }
        try {
            wrapp.issueCertificateForENIS(eInfo,ksInfo);
            assertTrue(false);
        }
        catch(IssueCertificateException e) {
            assertTrue(true);
        }
        try {
            wrapp.revokeEntityCertificate(null, null, null, null);
            assertTrue(false);
        } catch(RevokeEntityCertificateException e) {
            assertTrue(true);
        }
        try {
            wrapp.reIssueLegacyXMLCertificate(null, null, null, null, null);
            assertTrue(false);
        } catch (ReIssueLegacyXMLCertificateException e) {
            assertTrue(true);
        }

        //Mock
        CredMaExternalServiceApiWrapper extMockWrapp = wrappFactory.getInstance("MOCKED_API");
        assertTrue(extMockWrapp != null);
        CredMaServiceApiWrapperMock mockWrapp = (CredMaServiceApiWrapperMock) extMockWrapp;
        assertTrue(mockWrapp.getCredentialManagerInterfaceVersion().equals("mock"));
        assertTrue(mockWrapp.getCertificatesByEntityName("entityName", EntityType.ENTITY, CertificateStatus.ACTIVE) == null);
        assertTrue(mockWrapp.getEndEntitiesByCategory("UNDEFINED") == null);
        assertTrue(mockWrapp.issueCertificateForENIS(null, null) == null);
        assertTrue(mockWrapp.reIssueCertificate(null, null, null) == null);
        assertTrue(mockWrapp.revokeCertificate(null, null) == null);
        assertTrue(mockWrapp.revokeEntityCertificate(null, null, null, null) == null);
        assertTrue(mockWrapp.reIssueLegacyXMLCertificate(null, null, null, null, null) == null);
    }
    
    @Test
    public void testCredMaWrapperFactory() {
        
        CredMaServiceApiWrapperFactory wrappFactory = new CredMaServiceApiWrapperFactory();
        CredMaServiceApiWrapper intWrapp = null;
        try {
            intWrapp = wrappFactory.getInstance("FAKE_ENVIRONMENT");
            assertTrue(false);
        } catch(UnsupportedOperationException e) {
            assertTrue(intWrapp == null);
        }
        intWrapp = wrappFactory.getInstance("CREDMAN_SERVICE_API");
        assertTrue(intWrapp != null);
        CredMaServiceApiWrapperImpl wrapp = (CredMaServiceApiWrapperImpl) intWrapp;
        assertTrue(wrapp.getCredMaServiceApi() != null);
        
      //Mock
        CredMaServiceApiWrapper intMockWrapp = wrappFactory.getInstance("MOCKED_API");
        assertTrue(intMockWrapp != null);
        CredMaServiceApiWrapperMock mockWrapp = (CredMaServiceApiWrapperMock) intMockWrapp;

    }

} // end of file
