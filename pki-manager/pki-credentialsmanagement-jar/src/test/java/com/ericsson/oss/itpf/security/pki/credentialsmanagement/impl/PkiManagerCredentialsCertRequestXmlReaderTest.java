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
package com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.credentialsmanagement.constants.Constants;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.xml.model.*;

@RunWith(MockitoJUnitRunner.class)
public class PkiManagerCredentialsCertRequestXmlReaderTest {

    @Mock
    private CertificateType certificateType;

    @Mock
    private Logger logger;

    @InjectMocks
    private PkiManagerCredentialsCertRequestXmlReader pkiManagerCredentialsCertRequestXmlReader;

    @Mock
    private ApplicationsType applicationsType;

    @Mock
    private SubjectType subjectType;
    @Mock
    private TBSCertificateType tBSCertificateType;
    @Mock
    private KeyPairType keyPairType;

    private List<KeyStoreType> keyStoreTypeList;

    private List<TrustStoreType> trustStoreTypeList;

    private StoreType store;

    @Before
    public void setUpData() {
        keyStoreTypeList = new ArrayList<KeyStoreType>();

        KeyStoreType keyStoreType = new KeyStoreType();
        store = new StoreType();
        store.setStoreAlias("storename");
        store.setStoreLocation("default");
        store.setStorePassword("storePwd");
        keyStoreType.setPkcs12Keytore(store);
        keyStoreTypeList.add(keyStoreType);

        trustStoreTypeList = new ArrayList<TrustStoreType>();
        TrustStoreType trustStoreType = new TrustStoreType();
        trustStoreType.setJksTrustStore(store);
        trustStoreTypeList.add(trustStoreType);
    }

    @Test
    @Ignore
    public void testLoadDataFromXML() {
        File file = new File(Constants.PKI_CREDENTIALS_REQUEST_XML_FILE_PATH);
        Mockito.when(file.exists()).thenReturn(true);
        pkiManagerCredentialsCertRequestXmlReader.loadDataFromXML();
    }

    @Test(expected = CredentialsManagementServiceException.class)
    @Ignore
    public void testLoadDataFromXML_CredentialsManagementServiceException() {

        pkiManagerCredentialsCertRequestXmlReader.loadDataFromXML();
    }

    @Test
    public void testGetSubjectType() {
        Mockito.when(certificateType.getTbsCertificate()).thenReturn(tBSCertificateType);
        Mockito.when(certificateType.getTbsCertificate().getSubject()).thenReturn(subjectType);
        SubjectType subjectTypeResponse = pkiManagerCredentialsCertRequestXmlReader.getSubjectType();
        assertEquals(subjectType, subjectTypeResponse);
    }

    @Test
    public void testGetKeyPairType() {

        Mockito.when(certificateType.getKeyPair()).thenReturn(keyPairType);
        KeyPairType keyPairTypeRes = pkiManagerCredentialsCertRequestXmlReader.getKeyPairType();
        assertEquals(keyPairType, keyPairTypeRes);
    }

    @Test
    public void testGetStore_keystore_type_pkcs12() {

        Mockito.when(certificateType.getKeyStore()).thenReturn(keyStoreTypeList);

        StoreType storeType = pkiManagerCredentialsCertRequestXmlReader.getStore(com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.PKCS12);
        assertEquals(store.getStoreAlias(), storeType.getStoreAlias());
        assertEquals(store.getStoreLocation(), storeType.getStoreLocation());
    }

    @Test
    public void testGetStore_keystore_type_JKS() {

        Mockito.when(certificateType.getTrustStore()).thenReturn(trustStoreTypeList);

        StoreType storeType = pkiManagerCredentialsCertRequestXmlReader.getStore(com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.JKS);
        assertEquals(store.getStoreAlias(), storeType.getStoreAlias());
        assertEquals(store.getStoreLocation(), storeType.getStoreLocation());

    }

    @Test
    public void testGetEndEntityProfileName() {

        Mockito.when(certificateType.getEndEntityProfileName()).thenReturn("entityprofile");
        String endEntityProfileName = pkiManagerCredentialsCertRequestXmlReader.getEndEntityProfileName();
        assertEquals("entityprofile", endEntityProfileName);
    }

    @Test
    public void testGetOverlapPeriod() {
        Mockito.when(certificateType.getOverlapPeriod()).thenReturn("overlapperiod");
        String overlaPperiod = pkiManagerCredentialsCertRequestXmlReader.getOverlapPeriod();
        assertEquals("overlapperiod", overlaPperiod);
    }
}
