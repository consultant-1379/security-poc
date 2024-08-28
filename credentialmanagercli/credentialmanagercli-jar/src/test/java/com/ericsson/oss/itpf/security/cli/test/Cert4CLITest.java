package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.File;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

import javax.xml.bind.annotation.XmlElement;

import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.AppClientXmlConfiguration;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils.HostnameResolveUtil;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.ApplicationCertificateConfigInformation;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;



@RunWith(JUnit4.class)
public class Cert4CLITest {
	
		  final Properties props = PropertiesReader.getConfigProperties();

         // TORF-562254 update log4j
         private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();


	  @Test
	  public void testSubDNSubstitution(){
		  String host = "";
		  try {
				host = InetAddress.getLocalHost().getHostName();
				LOG.debug(" Hostname = " + host);
			} catch (UnknownHostException e) {
				
				e.printStackTrace();
			}
		  final File XMLfile = new File(this.getClass().getClassLoader().getResource("forCLIValidXMLJKS.xml").getFile());
		  ApplicationCertificateConfigInformation appConf = new AppClientXmlConfiguration(XMLfile);
		  LOG.debug(" hostname in certificate " + appConf.getApplicationsInfo().get(0).getCertificates().get(0).getTbsCertificate().getSubjectDN());
		  assertTrue("Should return true if the distinguishname is equal to CN=<hostname>", ("CN="+host).equals(appConf.getApplicationsInfo().get(0).getCertificates().get(0).getTbsCertificate().getSubjectDN()));
	  }

}
