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

import java.io.File;
//import java.io.IOException;
import java.util.Properties;

import javax.naming.NamingException;
import javax.xml.bind.JAXBException;

import org.apache.commons.cli.ParseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.xml.sax.SAXException;

//import com.ericsson.oss.itpf.security.credentialmanager.cli.business.ExecuteCommandsImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.AppClientXmlConfiguration;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.ApplicationCertificateConfigInformation;
//import com.ericsson.oss.itpf.security.credentialmanager.cli.util.LoggerPropertiesConstants;
//import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;



@RunWith(JUnit4.class)
public class TestXMLParser {

	{		  final Properties props = PropertiesReader
                .getConfigProperties();
				 props.setProperty("servicemanager.implementation", "MOCKED_API"); }
		
    
    	
    @Test
    public void testParseBasedValidXMLBASE64() throws NamingException, ParseException,JAXBException, SAXException         
    {
        final File createdFile = new File(this.getClass().getClassLoader().getResource("validXMLBASE64.xml").getFile());

        final ApplicationCertificateConfigInformation appClient = new AppClientXmlConfiguration(createdFile);
        
        assertTrue("Should return true if the distinguishname is equal to CN=atclvm387", "CN=atclvm387".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTbsCertificate().getSubjectDN()));

        assertTrue("Should return true if the endentityprofilename is equal to TOREndEntityProfile", "TOREndEntityProfile".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getEndEntityProfileName()));
        
  //    assertTrue("Should return true if the keypairsize is equal to 2048", "2048".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeypairSize()));

  //    assertTrue("Should return true if the keypairalgorithm is equal to RSA", "RSA".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeypairAlgorithm())); 
        
        assertTrue("Should return true if the keyfilelocation is equal to private.KEY", "certs/private.KEY".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeyStores().get(0).getPrivateKeyLocation()));

        assertTrue("Should return true if the certificatefilelocation is equal to cert.CER", "certs/cert.CER".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeyStores().get(0).getCertificateLocation()));

        assertTrue("Should return true if the Trust store location is equal to TestTS.pem", "certs/TestTS.pem".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getLocation()));
    }
    
        
        
    @Test
    public void testParseBasedValidXMLJKS() throws  NamingException, ParseException,JAXBException, SAXException   
    {
        final File createdFile = new File(this.getClass().getClassLoader().getResource("validXMLJKS.xml").getFile());

        final ApplicationCertificateConfigInformation appClient = new AppClientXmlConfiguration(createdFile);

        assertTrue("Should return true if the distinguishname is equal to CN=atclvm387", "CN=atclvm387".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTbsCertificate().getSubjectDN()));

        assertTrue("Should return true if the endentityprofilename is equal to TOREndEntityProfile", "TOREndEntityProfile".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getEndEntityProfileName()));
        
  //    assertTrue("Should return true if the keypairsize is equal to 2048", "2048".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeypairSize()));

  //    assertTrue("Should return true if the keypairalgorithm is equal to RSA", "RSA".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeypairAlgorithm())); 
        
        assertTrue("Should return true if the Keystorealias is equal to teste", "teste".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeyStores().get(0).getAlias()));

        assertTrue("Should return true if the Keystorelocation is equal to Teste.JKS", "certs/Teste.JKS".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeyStores().get(0).getKeyStorelocation()));
                
        assertTrue("Should return true if the Truststore storealias is equal to TestCA1", "TestCA1".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getAlias()));
 
        assertTrue("Should return true if the Truststore location is equal to TestTS.JKS", "certs/TestTS.JKS".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getLocation()));
                      
    }


    @Test
    public void testParseBasedValidXMLPKCS12() throws  NamingException, ParseException, JAXBException, SAXException     
    {   
        final File createdFile = new File(this.getClass().getClassLoader().getResource("validXMLPKCS12.xml").getFile());

        final ApplicationCertificateConfigInformation appClient = new AppClientXmlConfiguration(createdFile);
        
        assertTrue("Should return true if the distinguishname is equal to CN=atclvm387", "CN=atclvm387".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTbsCertificate().getSubjectDN()));

        assertTrue("Should return true if the endentityprofilename is equal to CMPRA_EP", "CMPRA_EP".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getEndEntityProfileName()));
        
   //   assertTrue("Should return true if the keypairsize is equal to 2048", "2048".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeypairSize()));

   //   assertTrue("Should return true if the keypairalgorithm is equal to RSA", "RSA".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeypairAlgorithm())); 
        
        assertTrue("Should return true if the Keystorealias is equal to keystore", "keystore".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeyStores().get(0).getAlias()));
                
        assertTrue("Should return true if the Keystoreocation is equal to keystore.p12", "certs/keystore.p12".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getKeyStores().get(0).getKeyStorelocation()));
                          
        assertTrue("Should return true if the Truststore storealias is equal to TestCA1", "truststore".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getAlias()));
 
        assertTrue("Should return true if the Truststore location is equal to keystore.p12", "certs/keystore.p12".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getLocation()));
          
        assertTrue("Should return true if the Truststore password is equal to changeit", "changeit".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getPassword()));
        
    }

   
}
