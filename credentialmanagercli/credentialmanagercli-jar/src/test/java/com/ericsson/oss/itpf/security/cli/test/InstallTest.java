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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;

import org.apache.commons.cli.ParseException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperImpl;
import com.ericsson.oss.itpf.security.credmsapi.api.InternalIfCredentialManagement;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.CredentialManagerCertificateExtension;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;

@RunWith(MockitoJUnitRunner.class)
public class InstallTest {

    @InjectMocks
    static CredMaServiceApiWrapperImpl serviceApi;
    @Mock
    static InternalIfCredentialManagement ifApiMock;

    CredentialManagerSubjectAltName subjectAltName;
    List<CredentialManagerKeyStore> keystoreInfoList;
    List<CredentialManagerTrustStore> truststoreInfoList;
    List<CredentialManagerTrustStore> crlstoreInfoList;
    CredentialManagerCertificateExt certificateExtension;

    @SuppressWarnings("unchecked")
    @Before
    public void mockingServicApi() {

        // prepare fake data for keystore
        this.keystoreInfoList = new ArrayList<>();
        this.truststoreInfoList = new ArrayList<>();
        this.crlstoreInfoList = new ArrayList<>();

        final KeyStoreType kst = new KeyStoreType();
        final KStoreType jks = new KStoreType();
        jks.setStorealias("pippo");
        jks.setStorelocation("testKs.jks");
        jks.setStorepassword("InstallTest");
        kst.setJkskeystore(jks);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        this.keystoreInfoList.add(keyStore);

        final TrustStoreType tst = new TrustStoreType();
        final TStoreType jks2 = new TStoreType();
        jks2.setStorealias("pippo");
        jks2.setStorelocation("testTs.jks");
        jks2.setStorepassword("InstallTest");
        tst.setJkstruststore(jks2);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        this.truststoreInfoList.add(trustStore);

        final TrustStoreType cst = new TrustStoreType();
        final Base64TStoreType b64 = new Base64TStoreType();
        b64.setStorealias("pippo");
        b64.setStorefolder("cert");
        //b64.setStorelocation("ks.pem");
        b64.setStorepassword("");
        cst.setBase64Truststore(b64);
        final CredentialManagerTrustStore crlStore = new CredentialManagerTrustStoreImpl(cst);
        this.crlstoreInfoList.add(crlStore);

        final List<List<String>> subjectAltNameList = new ArrayList<List<String>>();
        final List<String> dummyList = new ArrayList<String>();
        dummyList.add("subjectAltName");
        subjectAltNameList.add(dummyList);//when SubjectAlternateNameImpl is called the type will be set to NOVALUE
        final SubjectAlternativeNameType subjectAltNameType = new SubjectAlternativeNameType();
        final List<String> ipaddress = new ArrayList<String>();
        ipaddress.add("1.1.1.1");
        subjectAltNameType.setIpaddress(ipaddress);
        final List<String> dns = new ArrayList<String>();
        dns.add("openDNS.org");
        subjectAltNameType.setDns(dns);
        this.subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subjectAltNameType);
        this.subjectAltName.setValue(subjectAltNameList);
        //final String entityProfileName = "entityProfileName";
        final CertificateExtensionType certExtType = new CertificateExtensionType();
        //certExtType.setSubjectalternativename(subjectAltNameType);
        this.certificateExtension = new CredentialManagerCertificateExtImpl(certExtType);

        //serviceApi.setCredMaServiceApi(ifApiMock);

        try {
            when(
                    InstallTest.ifApiMock.issueCertificate(Matchers.any(String.class), Matchers.any(String.class), Matchers.any(SubjectAlternativeNameType.class), Matchers.any(String.class),
                            Matchers.any(List.class), Matchers.any(List.class), Matchers.any(List.class), Matchers.any(CredentialManagerCertificateExtension.class), Matchers.any(boolean.class)))
                    .thenReturn(true);

            when(
                    InstallTest.ifApiMock.issueCertificateRESTchannel(Matchers.any(String.class), Matchers.any(String.class), Matchers.any(SubjectAlternativeNameType.class),
                            Matchers.any(String.class), Matchers.any(List.class), Matchers.any(List.class), Matchers.any(List.class), Matchers.any(CredentialManagerCertificateExtension.class),
                            Matchers.any(Boolean.class), Matchers.any(Boolean.class), Matchers.any(Boolean.class))).thenReturn(true);

        } catch (final IssueCertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    @Test
    public void testManageCertificateAndTrust() throws NamingException, ParseException, IOException {

        // call service but intercepted by mockito
        Boolean res = false;
        res = serviceApi.manageCertificateAndTrust("entityName", "distinguishName", this.subjectAltName, "entityProfileName", this.keystoreInfoList, this.truststoreInfoList, this.crlstoreInfoList,
                this.certificateExtension, false, true);

        assertEquals("Should return True", true, res.booleanValue());
        
        // Same test but with certificateChain parameter set to true:
        res = false;
        res = serviceApi.manageCertificateAndTrust("entityName", "distinguishName", this.subjectAltName, "entityProfileName", this.keystoreInfoList, this.truststoreInfoList, this.crlstoreInfoList,
                this.certificateExtension, true, true);

        assertEquals("Should return True", true, res.booleanValue());
    }

    @Test
    public void testManageCredMaCertificate() throws NamingException, ParseException, IOException {

        // call service but intercepted by mockito
        Boolean res = false;
        res = serviceApi.manageCredMaCertificate("entityName", "distinguishName", this.subjectAltName, "entityProfileName", this.keystoreInfoList, this.truststoreInfoList, this.crlstoreInfoList,
                this.certificateExtension, false, false, false, false);

        assertEquals("Should return True", true, res.booleanValue());
    }

}
