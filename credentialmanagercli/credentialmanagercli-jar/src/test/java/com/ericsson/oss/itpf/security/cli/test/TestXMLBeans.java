package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Properties;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

@RunWith(JUnit4.class)
public class TestXMLBeans {

    {
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API");
    }

    final String username = "Pippo";
    final String usergroup = "Pippo";
    final String endentityprofilename = "Pippo";
    final String alias = "Pippo";
    final String location = "Pippo";
    final String algorithm = "DES";
    final String password = "Pippo";
    final BigInteger uno = BigInteger.valueOf(1);

    KStoreType kStore;
    Base64KStoreType base64KStore;
    TStoreType tStore;
    Base64TStoreType base64TStore;
    KeyRequestsType KeyRequest;
    CrlStoreType crlStore;
    TBSCertificateType tbscertificate;
    KeypairType keypair;
    CertificateExtensionType alternativename;
    ArrayList<SecretKeyRequestType> secretKeyList;
    ArrayList<KeyPairRequestType> keyPairList;

    @Before
    public void dataInit() {
        this.kStore = new KStoreType();
        this.kStore.setStorealias(this.alias);
        this.kStore.setStorelocation(this.location);
        this.kStore.setStorepassword(this.password);
        this.base64KStore = new Base64KStoreType();
        this.base64KStore.setStorealias(this.alias);
        this.base64KStore.setCertificatefilelocation(this.location);
        this.base64KStore.setKeyfilelocation(this.location);
        this.base64KStore.setStorelocation(this.location);
        this.base64KStore.setStorepassword(this.password);
        this.tStore = new TStoreType();
        this.tStore.setStorealias(this.alias);
        this.tStore.setStorelocation(this.location);
        this.tStore.setStorefolder(this.location);
        this.tStore.setStorepassword(this.password);
        this.base64TStore = new Base64TStoreType();
        this.base64TStore.setStorealias(this.alias);;
        this.base64TStore.setStorelocation(this.location);
        this.base64TStore.setStorefolder(this.location);
        this.base64TStore.setStorepassword(this.password);
        this.keypair = new KeypairType();
        this.keypair.setKeypairalgorithm(this.algorithm);
        this.keypair.setKeypairsize(this.uno);
    }

    public void checkKStore(final KStoreType kStore) {
        assertTrue("ksStoreType alias", this.alias.equals(kStore.getStorealias()));
        assertTrue("ksStoreType storelocation", this.location.equals(kStore.getStorelocation()));
        assertTrue("ksStoreType getStorepassword", this.location.equals(kStore.getStorepassword()));
    }
    
    public void checkTStore(final TStoreType tStore) {
        assertTrue("ksStoreType alias", this.alias.equals(tStore.getStorealias()));
        assertTrue("ksStoreType storelocation", this.location.equals(tStore.getStorelocation()));
        assertTrue("ksStoreType getStorefolder", this.location.equals(tStore.getStorefolder()));
        assertTrue("ksStoreType getStorepassword", this.location.equals(tStore.getStorepassword()));
    }


    public void checkBase64KStore(final Base64KStoreType base64kStore) {
        assertTrue("Base64StoreType alias", this.alias.equals(base64kStore.getStorealias()));
        assertTrue("Base64StoreType storelocation", this.location.equals(base64kStore.getStorelocation()));
        assertTrue("Base64StoreType getCertificatefilelocation", this.location.equals(base64kStore.getCertificatefilelocation()));
        assertTrue("Base64StoreType getKeyfilelocation", this.location.equals(base64kStore.getKeyfilelocation()));
        assertTrue("Base64StoreType getStorepassword", this.location.equals(base64kStore.getStorepassword()));
    }

    public void checkBase64TStore(final Base64TStoreType base64tStore) {
        assertTrue("Base64StoreType alias", this.alias.equals(base64tStore.getStorealias()));
        assertTrue("Base64StoreType storelocation", this.location.equals(base64tStore.getStorelocation()));
        assertTrue("Base64StoreType getStorefolder", this.location.equals(base64tStore.getStorefolder()));
        assertTrue("Base64StoreType getStorepassword", this.location.equals(base64tStore.getStorepassword()));
    }
    
    @Test
    public void testUserType() {
        final UserType user = new UserType();
        user.setUsername(this.username);
        user.setUsergroup(this.usergroup);

        assertTrue("userType.username", this.username.equals(user.getUsername()));
        assertTrue("userType.usergroup", this.usergroup.equals(user.getUsergroup()));
    }

    @Test
    public void testCertificateType() {
        final CertificateType certificate = new CertificateType();

        certificate.setEndentityprofilename(this.endentityprofilename);

        this.tbscertificate = new TBSCertificateType();
        this.alternativename = new CertificateExtensionType();
        this.tbscertificate.setCertificateextension(this.alternativename);
        certificate.setTbscertificate(this.tbscertificate);

        certificate.setKeypair(this.keypair);

        assertTrue("certificate.getEndentityprofilename", this.endentityprofilename.equals(certificate.getEndentityprofilename()));
        assertTrue("certificate.getTbscertificate", this.alternativename.equals(certificate.getTbscertificate().getCertificateextension()));
        assertTrue("certificate.getKeypair", this.algorithm.equals(certificate.getKeypair().getKeypairalgorithm()));
        assertTrue("certificate.getKeypair", this.uno.equals(certificate.getKeypair().getKeypairsize()));
    }

    @Test
    public void testTrustStoreType() {
        final TrustStoreType trustStore = new TrustStoreType();
        trustStore.setJkstruststore(this.tStore);
        trustStore.setPkcs12Truststore(this.tStore);
        trustStore.setJcekstruststore(this.tStore);

        //assert
        this.checkTStore(trustStore.getJkstruststore());
        this.checkTStore(trustStore.getPkcs12Truststore());
        this.checkTStore(trustStore.getJcekstruststore());
    }

    @Test
    public void testSecretStoreType() {
        final SecretStoreType secretStore = new SecretStoreType();
        secretStore.setBase64Secretstore(this.base64KStore);
        secretStore.setPkcs12Secretstore(this.kStore);
        secretStore.setJcekssecretstore(this.kStore);

        //assert
        this.checkBase64KStore(secretStore.getBase64Secretstore());
        this.checkKStore(secretStore.getPkcs12Secretstore());
        this.checkKStore(secretStore.getJcekssecretstore());
    }

    @Test
    public void testCrlStoreType() {
        final CrlStoreType crlStore = new CrlStoreType();
        crlStore.setBase64Crlstore(this.base64TStore);
        //crlStore.setPkcs12Crlstore(ksStore);

        assertTrue("crlStore.getBase64Crlstore", this.base64TStore.equals(crlStore.getBase64Crlstore()));
        //assertTrue("crlStore.getPkcs12Crlstore", ksStore.equals(crlStore.getPkcs12Crlstore()));
    }

    @Test
    public void testKeyRequestsType() {
        KeyPairRequestType keyPairRequest; // definisco oggetto che poi istanzio
                                           // ??????
        keyPairRequest = new KeyPairRequestType(); // istanzio oggetto keyPair
        keyPairRequest.setKeyalgorithm(this.algorithm); // riempio oggetto creato con
        // oggetti dati dal metodo
        // della classe
        keyPairRequest.setKeysize(this.uno);
        final KeyPairStoreType keypairStore = new KeyPairStoreType();
        keypairStore.setBase64Keypairstore(this.base64KStore);
        keyPairRequest.getKeystore().add(keypairStore);

        SecretKeyRequestType secretKeyRequest;
        secretKeyRequest = new SecretKeyRequestType(); // istanzio
                                                       // oggetto
                                                       // keyPair
        secretKeyRequest.setKeyalgorithm(this.algorithm); // riempio oggetto creato
                                                          // con oggetti dati dal
                                                          // metodo della classe
        secretKeyRequest.setKeysize(this.uno);
        final SecretStoreType secretStore = new SecretStoreType();
        secretStore.setPkcs12Secretstore(this.kStore);
        secretKeyRequest.getKeystore().add(secretStore);

        final KeyRequestsType keyRequests = new KeyRequestsType();
        keyRequests.getKeypairrequest().add(keyPairRequest);
        keyRequests.getSecretkeyrequest().add(secretKeyRequest);

        // assert
        assertTrue("keyPair keyAlgorithm", this.algorithm.equals(keyRequests.getKeypairrequest().get(0).getKeyalgorithm()));
        assertTrue("keyPair keySize", this.uno.equals(keyRequests.getKeypairrequest().get(0).getKeysize()));
        this.checkBase64KStore(keyRequests.getKeypairrequest().get(0).getKeystore().get(0).getBase64Keypairstore());

        assertTrue("secretKey.keyAlgorithm", this.algorithm.equals(keyRequests.getSecretkeyrequest().get(0).getKeyalgorithm()));
        assertTrue("secretKey.keySize", this.uno.equals(keyRequests.getSecretkeyrequest().get(0).getKeysize()));
        this.checkKStore(keyRequests.getSecretkeyrequest().get(0).getKeystore().get(0).getPkcs12Secretstore());

    }

}
