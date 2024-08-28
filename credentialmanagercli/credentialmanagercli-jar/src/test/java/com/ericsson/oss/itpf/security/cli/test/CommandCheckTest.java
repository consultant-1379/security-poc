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
import java.util.List;
import java.util.Properties;

import javax.naming.NamingException;

import org.apache.commons.cli.ParseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Matchers;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.CommandCheck;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;
import com.ericsson.oss.itpf.security.credmsapi.business.exceptions.SystemManagementException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.SystemManagement;

@RunWith(PowerMockRunner.class)
@PrepareForTest(SystemManagement.class)
public class CommandCheckTest {
    
    
   @Test
    public void testMockedCheck() throws NamingException, ParseException, IOException {

        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API"); 
                         
        final File createdFile = new File(this.getClass().getClassLoader().getResource("CheckValidXMLBASE64.xml").getFile());

        //final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory
        //        .getInstance(createdFile);
        
        final CommandCheck command = new CommandCheck(createdFile, false);
        
        final List<String> arg = command.getValidArguments();
        assertTrue("valid args", !arg.isEmpty());
        
        int res = 1;
        res = command.execute();
        System.out.println(" returned " + res);
        assertEquals("Should return 0", 0, res);
        
    }
   
   @Test
   public void testMockedCheckRestart() throws NamingException, ParseException, IOException {
       
       final Properties props = PropertiesReader.getConfigProperties();
       props.setProperty("servicemanager.implementation", "MOCKED_API");
       
       PowerMockito.mockStatic(SystemManagement.class);
       PowerMockito.doNothing().when(SystemManagement.class);
       
     //HTTP connector restart
       final File createdFile2 = new File(this.getClass().getClassLoader().getResource("validXMLRestartJKS.xml").getFile());

       final CommandCheck command2 = new CommandCheck(createdFile2, false);
       
       final List<String> arg2 = command2.getValidArguments();
       assertTrue("valid args2 ", !arg2.isEmpty());
       
       int res2 = 1;
       res2 = command2.execute();
       System.out.println("2) returned " + res2);
       assertEquals("2) Should return 0", 0, res2);
   }
   
   @Test
   public void testMockedCheckVMRestartFail() throws NamingException, ParseException, IOException {
       
       final Properties props = PropertiesReader.getConfigProperties();
       props.setProperty("servicemanager.implementation", "MOCKED_API");

       //VM restart
       final File createdFile3 = new File(this.getClass().getClassLoader().getResource("validXMLVMRestartJKS.xml").getFile());

       final CommandCheck command3 = new CommandCheck(createdFile3, false);
       
       final List<String> arg3 = command3.getValidArguments();
       assertTrue("valid args3 ", !arg3.isEmpty());
       
       int res3 = 1;
       res3 = command3.execute();
       System.out.println("3) returned " + res3);
       assertEquals("3) Should return 0", 0, res3);
   }
   
   @Test
   public void testMockedCheckRestartFails() throws Exception {
       
       final Properties props = PropertiesReader.getConfigProperties();
       props.setProperty("servicemanager.implementation", "MOCKED_API");

       PowerMockito.mockStatic(SystemManagement.class);
       PowerMockito.doThrow(new SystemManagementException()).when(SystemManagement.class, "restartHttpConnector", Matchers.anyInt());
       PowerMockito.doThrow(new SystemManagementException()).when(SystemManagement.class, "restartHttpConnector", Matchers.anyInt(),Matchers.anyInt());
       PowerMockito.doThrow(new SystemManagementException()).when(SystemManagement.class, "restartHttpConnector", Matchers.anyInt(),Matchers.anyString(),Matchers.anyInt());

     //HTTP connector restart
       final File createdFile4 = new File(this.getClass().getClassLoader().getResource("validXMLRestartJKS.xml").getFile());

       final CommandCheck command4 = new CommandCheck(createdFile4, false);
       
       final List<String> arg4 = command4.getValidArguments();
       assertTrue("valid args4 ", !arg4.isEmpty());
       
       int res4 = 1;
       res4 = command4.execute();
       System.out.println("4) returned " + res4);
       assertEquals("4) Should return 0", 0, res4);
   }
   
}
