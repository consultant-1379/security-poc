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

import static org.junit.Assert.*;

import java.io.File;
import java.io.IOException;
import java.util.*;

import javax.naming.NamingException;

import org.apache.commons.cli.ParseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.CommandInstall;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiWrapperFactory;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

@RunWith(JUnit4.class)
public class InstallMockTest {

    @Test
    public void testNotMockedInstall() throws NamingException, ParseException, IOException {

        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API");

        final File createdFile = new File(this.getClass().getClassLoader().getResource("validXMLJKS.xml").getFile());

        //final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory
        //        .getInstance(createdFile);
        final CommandInstall command = new CommandInstall(createdFile);

        int res = 0;
        res = command.execute();

        final List<String> arg = command.getValidArguments();
        assertTrue("valid args", !arg.isEmpty());

        assertEquals("Should return 0", 0, res);

    }

    @Test
    public void testMockedJKSInstall() throws NamingException, ParseException, IOException {

        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API");

        final CredMaServiceApiWrapper serviceApi = new CredMaServiceApiWrapperFactory().getInstance(props.getProperty("servicemanager.implementation"));

        // prepare fake data for keystore
        final List<CredentialManagerKeyStore> keystoreInfoList = new ArrayList<>();
        final List<CredentialManagerTrustStore> truststoreInfoList = new ArrayList<>();
        final List<CredentialManagerTrustStore> crlstoreInfoList = new ArrayList<>();

        final KeyStoreType kst = new KeyStoreType();
        final KStoreType jks = new KStoreType();
        jks.setStorealias("pippo");
        jks.setStorelocation("testKs.jks");
        jks.setStorepassword("InstallTest");
        kst.setJkskeystore(jks);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        keystoreInfoList.add(keyStore);

        final TrustStoreType tst = new TrustStoreType();
        final TStoreType jks2 = new TStoreType();
        jks2.setStorealias("pippo");
        jks2.setStorelocation("testTs.jks");
        jks2.setStorepassword("InstallTest");
        tst.setJkstruststore(jks2);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        truststoreInfoList.add(trustStore);

        final List<List<String>> subjectAltNameList = new ArrayList<List<String>>();
        final List<String> dummyList = new ArrayList<String>();
        dummyList.add("subjectAltName");
        subjectAltNameList.add(dummyList);//when SubjectAlternateNameImpl is called the type will be set to NOVALUE
        final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAlternateNameImpl(null);
        subjectAltName.setValue(subjectAltNameList);
        final String entityProfileName = null;
        final CredentialManagerCertificateExt certificateExtension = null;

        // call mocked API (it creates fake keystore files)
        serviceApi.manageCertificateAndTrust("entityName", "distinguishName", subjectAltName, entityProfileName, keystoreInfoList, truststoreInfoList, crlstoreInfoList, certificateExtension, false,
                false);

        // check if the files have been created
        assertTrue("check file" + keyStore.getKeyStorelocation(), keyStore.exists());
        assertTrue("check file" + trustStore.getLocation(), trustStore.exists());

        // delete files
        final File file1 = new File(keyStore.getKeyStorelocation());
        file1.delete();
        final File file2 = new File(trustStore.getLocation());
        file2.delete();
    }

    @Test
    public void testMockedBase64Install() throws NamingException, ParseException, IOException {

        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API");

        final CredMaServiceApiWrapper serviceApi = new CredMaServiceApiWrapperFactory().getInstance(props.getProperty("servicemanager.implementation"));

        // prepare fake data for keystore
        final List<CredentialManagerKeyStore> keystoreInfoList = new ArrayList<>();
        final List<CredentialManagerTrustStore> truststoreInfoList = new ArrayList<>();
        final List<CredentialManagerTrustStore> crlstoreInfoList = new ArrayList<>();

        final KeyStoreType kst = new KeyStoreType();
        final Base64KStoreType b64 = new Base64KStoreType();
        b64.setStorealias("pippo");
        b64.setCertificatefilelocation("cert.cer");
        b64.setKeyfilelocation("key.key");
        b64.setStorepassword("InstallTest");
        kst.setBase64Keystore(b64);
        final CredentialManagerKeyStore keyStore = new CredentialManagerKeyStoreImpl(kst);
        keystoreInfoList.add(keyStore);

        final TrustStoreType tst = new TrustStoreType();
        final Base64TStoreType b64_2 = new Base64TStoreType();
        b64_2.setStorealias("pippo");
        b64_2.setStorelocation("testTs.jks");
        b64_2.setStorepassword("InstallTest");
        tst.setBase64Truststore(b64_2);
        final CredentialManagerTrustStore trustStore = new CredentialManagerTrustStoreImpl(tst);
        truststoreInfoList.add(trustStore);

        final List<List<String>> subjectAltNameList = new ArrayList<List<String>>();
        final List<String> dummyList = new ArrayList<String>();
        dummyList.add("subjectAltName");
        subjectAltNameList.add(dummyList);//when SubjectAlternateNameImpl is called the type will be set to NOVALUE
        final CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAlternateNameImpl(null);
        subjectAltName.setValue(subjectAltNameList);
        final String entityProfileName = null;
        final CredentialManagerCertificateExt certificateExtension = null;

        // call mocked API (it creates fake keystore files)
        serviceApi.manageCertificateAndTrust("entityName", "distinguishName", subjectAltName, entityProfileName, keystoreInfoList, truststoreInfoList, crlstoreInfoList, certificateExtension, false,
                false);

        // check if the files have been created
        assertTrue("check file" + keyStore.getCertificateLocation(), keyStore.exists());
        assertTrue("check file" + keyStore.getPrivateKeyLocation(), keyStore.exists());
        assertTrue("check file" + trustStore.getLocation(), trustStore.exists());

        // delete files
        final File file1 = new File(keyStore.getCertificateLocation());
        file1.delete();
        final File file2 = new File(keyStore.getPrivateKeyLocation());
        file2.delete();
        final File file3 = new File(trustStore.getLocation());
        file3.delete();
    }

}
