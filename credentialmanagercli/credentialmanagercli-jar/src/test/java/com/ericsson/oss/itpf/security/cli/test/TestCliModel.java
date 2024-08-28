package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerApplicationImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerApplicationsImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerCertificateImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerCheckActionImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerKeyStoreImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerPostScriptCallerImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerTBSCertificateImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerTrustStoreImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerTrustStoreOnlyImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ApplicationType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ApplicationsType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.Base64KStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.Base64TStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CertificateType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CertificatesType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CheckActionType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CommandType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CrlSourceType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CrlStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.KStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.KeyStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.SubjectType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TBSCertificateType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustSourceType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustStoreOnlyType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustStoresOnlyType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCommandType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.StoreConstants;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TestCliModel {

   
    @Test
    public void CredentialManagerApplicationImplTest() {
        CredentialManagerApplicationImpl applImpl = null;
        try {
            applImpl = new CredentialManagerApplicationImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(applImpl == null);
        }
        try {
            applImpl = new CredentialManagerApplicationImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(applImpl == null);
        }
        ApplicationType appType = new ApplicationType();
        applImpl = new CredentialManagerApplicationImpl(appType);
        assertTrue(applImpl.getCertificates().isEmpty() && applImpl.getTrustStoresOnly().isEmpty());
        appType.setCertificates(new CertificatesType());
        appType.setTruststores(new TrustStoresOnlyType());
        applImpl = new CredentialManagerApplicationImpl(appType);
        assertTrue(applImpl.getCertificates().isEmpty() && applImpl.getTrustStoresOnly().isEmpty());
    }
    
    @Test
    public void CredentialManagerApplicationsImplTest() {
        
        CredentialManagerApplicationsImpl cmApps = null;
        try {
            cmApps = new CredentialManagerApplicationsImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmApps == null);
        }
        try {
            cmApps = new CredentialManagerApplicationsImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmApps == null);
        }
        ApplicationsType appType = new ApplicationsType();
        cmApps = new CredentialManagerApplicationsImpl(appType);
        assertTrue(cmApps.getApplications().isEmpty());
    }
    
    @Test
    public void CredentialManagerCertificateImplTest() {
        CredentialManagerCertificateImpl certImpl = null;
        try {
            certImpl = new CredentialManagerCertificateImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(certImpl == null);
        }
        try {
            certImpl = new CredentialManagerCertificateImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(certImpl == null);
        }
        CertificateType certType = new CertificateType();
        certType.setCertificatechain(true);
        certType.setEndentityprofilename("entityProfile");
        certType.setTbscertificate(new TBSCertificateType());
        certImpl= new CredentialManagerCertificateImpl(certType);
        assertTrue(certImpl.getSignatureAlgorithm().equals("SHA256WithRSAEncryption"));
        assertTrue(certImpl.getKeypairAlgorithm() == null && certImpl.getKeypairSize() == null);
        assertTrue(certImpl.getConnectorManaged() == null);     
    }
    
    @Test
    public void CredentialManagerCheckActionImplTest() {
        
        CredentialManagerCheckActionImpl cmCheck = null;
        try {
            cmCheck = new CredentialManagerCheckActionImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmCheck == null);
        }
        try {
            cmCheck = new CredentialManagerCheckActionImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmCheck == null);
        }
        CheckActionType chAction = new CheckActionType();
        cmCheck = new CredentialManagerCheckActionImpl(chAction);
        assertTrue(cmCheck.getCheckcause().isEmpty());
    }
    
    @Test
    public void CredentialManagerKeyStoreImplTest() {
        
        CredentialManagerKeyStoreImpl cmKS = null;
        try {
            cmKS = new CredentialManagerKeyStoreImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmKS == null);
        }
        try {
            cmKS = new CredentialManagerKeyStoreImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmKS == null);
        }
        KeyStoreType ksType = new KeyStoreType();
        ksType.setBase64Keystore(new Base64KStoreType());
        ksType.setJcekskeystore(new KStoreType());
        ksType.setJkskeystore(new KStoreType());
        ksType.setPkcs12Keystore(new KStoreType());
        cmKS = new CredentialManagerKeyStoreImpl(ksType);
        assertTrue(cmKS.getType().equals(StoreConstants.BASE64_STORE_TYPE)); //inside the code it is the last one type set

        KStoreType ksStore = new KStoreType();
        ksStore.setStorepassword("acde");
        ksType.setJcekskeystore(ksStore);
        cmKS = null;
        try {
            cmKS = new CredentialManagerKeyStoreImpl(ksType);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmKS == null);
        }

        ksStore.setStorepassword("");
        ksStore.setStorealias("alias");
        ksStore.setStorelocation("/tmp/location");
        ksType.setJcekskeystore(ksStore);
        cmKS = new CredentialManagerKeyStoreImpl(ksType);
        assertTrue(cmKS.getPassword().equals(""));
        cmKS.delete();
    }
    
    @Test
    public void CredentialManagerPostScriptCallerImplTest(){
        CredentialManagerPostScriptCallerImpl cmPS= new CredentialManagerPostScriptCallerImpl();
        CredentialManagerCommandType cmType = new CredentialManagerCommandType();
        cmType.addPathname("/tmp");
        cmType.addPathname("/tmp/folder");
        cmType.addParameterName("param");
        cmType.addParameterName("param2");
        cmType.addParameterValue("1");
        cmType.addParameterValue("2");
        cmPS.setPostScriptCmd(cmType);
        assertTrue(cmPS.getPostScriptCmd().getPathname().get(0).equals("/tmp") && cmPS.getPostScriptCmd().getPathname().get(1).equals("/tmp/folder"));
        cmPS.importPostScriptCmd(null);
        cmPS.importPostScriptCmd(new CommandType());
        assertTrue(cmPS.getPostScriptCmd().getPathname().isEmpty());
    }
    
    @Test
    public void CredentialManagerTBSCertificateImplTest() {
        
        CredentialManagerTBSCertificateImpl cmTBS = null;
        try {
            cmTBS = new CredentialManagerTBSCertificateImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTBS == null);
        }
        try {
            cmTBS = new CredentialManagerTBSCertificateImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTBS == null);
        }
        TBSCertificateType tbType = new TBSCertificateType();
        cmTBS = new CredentialManagerTBSCertificateImpl(tbType);
        assertTrue(cmTBS.getSubjectDN() == null);
        SubjectType subType = new SubjectType();
        subType.setEntityname("entityName");
        subType.setDistinguishname("CN=cn,,D=invalid");
        tbType.setSubject(subType);
        cmTBS = null;
        try {
            cmTBS = new CredentialManagerTBSCertificateImpl(tbType);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTBS == null);
        }
        subType.setDistinguishname("CN=cn,O=org");
        tbType.setSubject(subType);
        cmTBS = new CredentialManagerTBSCertificateImpl(tbType);
        assertTrue(cmTBS.getSubjectDN().equals(subType.getDistinguishname()));
    }
    
    @Test
    public void CredentialManagerTrustStoreImplTest() {
        
        CredentialManagerTrustStoreImpl cmTS = null;
        try {
            cmTS = new CredentialManagerTrustStoreImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTS == null);
        }
        try {
            cmTS = new CredentialManagerTrustStoreImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTS == null);
        }
        TrustStoreType tsType = new TrustStoreType();
        tsType.setBase64Truststore(new Base64TStoreType());
        tsType.setJcekstruststore(new TStoreType());
        tsType.setJkstruststore(new TStoreType());
        tsType.setPkcs12Truststore(new TStoreType());
        cmTS = new CredentialManagerTrustStoreImpl(tsType);
        assertTrue(cmTS.getType().equals(StoreConstants.BASE64_STORE_TYPE)); //inside the code it is the last one type set

        TStoreType tsStore = new TStoreType();
        tsStore.setStorepassword("acde");
        tsType.setJcekstruststore(tsStore);
        tsType.setTrustsource(TrustSourceType.INTERNAL);
        cmTS = null;
        try {
            cmTS = new CredentialManagerTrustStoreImpl(tsType);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTS == null);
        }

        tsStore.setStorepassword("");
        tsStore.setStorealias("alias");
        tsStore.setStorelocation("/tmp/location");
        tsType.setJcekstruststore(tsStore);
        cmTS = new CredentialManagerTrustStoreImpl(tsType);
        assertTrue(cmTS.getPassword().equals(""));
        
        
        CrlStoreType crlType = new CrlStoreType();
        crlType.setBase64Crlstore(new Base64TStoreType());
        cmTS = new CredentialManagerTrustStoreImpl(crlType);
        assertTrue(cmTS.getType().equals(StoreConstants.BASE64_STORE_TYPE)); //inside the code it is the last one type set

        Base64TStoreType crlStore = new Base64TStoreType();
        crlType.setBase64Crlstore(crlStore);
        crlType.setCrlsource(CrlSourceType.INTERNAL);
        cmTS = new CredentialManagerTrustStoreImpl(crlType);
        assertTrue(cmTS.getSource().equals(CrlSourceType.INTERNAL.toString().toLowerCase()));
    }
    
    @Test
    public void CredentialManagerTrustStoreOnlyImplTest() {
        
        CredentialManagerTrustStoreOnlyImpl cmTSO = null;
        try {
            cmTSO = new CredentialManagerTrustStoreOnlyImpl(null);
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTSO == null);
        }
        try {
            cmTSO = new CredentialManagerTrustStoreOnlyImpl("string");
            assertTrue(false);
        } catch (CredentialManagerException e) {
            assertTrue(cmTSO == null);
        }
        
        TrustStoreOnlyType tsOT = new TrustStoreOnlyType();
        cmTSO = new CredentialManagerTrustStoreOnlyImpl(tsOT);
    }
    
}
