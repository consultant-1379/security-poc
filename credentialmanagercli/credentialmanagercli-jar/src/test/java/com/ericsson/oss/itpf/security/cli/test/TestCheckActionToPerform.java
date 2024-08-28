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
import java.util.*;

import javax.naming.NamingException;
import javax.xml.bind.JAXBException;

import org.apache.commons.cli.ParseException;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.xml.sax.SAXException;

import com.ericsson.oss.itpf.security.credentialmanager.cli.implementation.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.CredentialManagerCheckActionImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ActionCauseType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ActionType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CheckActionType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CommandType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.ParameterType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.ActionListManager;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.Actions;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CreateActionElement;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.business.CredMaServiceApiControllerImpl;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.CheckResult;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;


@RunWith(JUnit4.class)
public class TestCheckActionToPerform {

    {
        final Properties props = PropertiesReader.getConfigProperties();
        props.setProperty("servicemanager.implementation", "MOCKED_API");
    }

    @Test
    public void testCheckValidXMLJKS() throws NamingException, ParseException, JAXBException, SAXException {
        final File createdFile = new File(this.getClass().getClassLoader().getResource("validXMLActionJKS.xml").getFile());

        final CredMaServiceApiController serviceController = new CredMaServiceApiControllerImpl();
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(createdFile);
        final List<Actions> ListActionToDo = serviceController.checkActionToPerform(appClientConfig, true);

        assertTrue("List Action should have one element", ListActionToDo.size() > 0);

        assertTrue("Action in the first element = RunScript", ListActionToDo.get(0).getAction().equals(CredentialManagerActionEnum.RUN_SCRIPT));

        assertTrue("Command pathname = helloworld.sh", ListActionToDo.get(0).getCommand().getPathname().get(0).equals("helloworld.sh"));

        // assertTrue("Should return true if the Trust store location is equal to TestTS.pem",
        // "certs/TestTS.pem".equals(appClient.getApplicationsInfo().get(0).getCertificates().get(0).getTrustStores().get(0).getLocation()));
    }

    @Test
    public void testNoActionValidXMLJKS() throws NamingException, ParseException, JAXBException, SAXException {
        final File pathFromResource = new File(this.getClass().getClassLoader().getResource("validNoActionJKS.xml").getFile());

        final CredMaServiceApiController serviceController = new CredMaServiceApiControllerImpl();
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(pathFromResource);
        final List<Actions> ListActionToDo = serviceController.checkActionToPerform(appClientConfig, true);

        assertTrue("List Action should have no element", ListActionToDo.size() == 0);
        final CommandCheck cmd = new CommandCheck(pathFromResource, true);
        cmd.execute();

    }

    @Test
    public void testDuplicateCheckValidXMLJKS() throws NamingException, ParseException, JAXBException, SAXException {
        final File createdFile = new File(this.getClass().getClassLoader().getResource("validDuplicateXMLActionJKS.xml").getFile());

        final CredMaServiceApiController serviceController = new CredMaServiceApiControllerImpl();
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(createdFile);
        final List<Actions> ListActionToDo = serviceController.checkActionToPerform(appClientConfig, true);

        assertTrue("List Action should have one element", ListActionToDo.size() == 2);

        assertTrue("Action in the first element = RunScript", ListActionToDo.get(0).getAction().equals(CredentialManagerActionEnum.RUN_SCRIPT));

        assertTrue("Command pathname = helloworld.sh", ListActionToDo.get(0).getCommand().getPathname().get(0).equals("helloworld.sh"));

        assertTrue("Command Elm[0] parameter portvalue  = 1024", ListActionToDo.get(0).getCommand().getParameterValue().get(0).equals("1024"));

        assertTrue("Command Elm[1] parameter portvalue  = 1023", ListActionToDo.get(1).getCommand().getParameterValue().get(0).equals("1023"));

    }

    @Test
    public void testNullCheckValidXMLJKS() throws NamingException, ParseException, JAXBException, SAXException {
        final File createdFile = new File(this.getClass().getClassLoader().getResource("validNullXMLActionJKS.xml").getFile());

        final CredMaServiceApiController serviceController = new CredMaServiceApiControllerImpl();
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(createdFile);
        final List<Actions> ListActionToDo = serviceController.checkActionToPerform(appClientConfig, true);

        assertTrue("List Action should have one element", ListActionToDo.size() == 3);

    }

    @Test
    public void testActionRunScriptWithParam() throws NamingException, ParseException, JAXBException, SAXException {
        File pathFromResource = new File(this.getClass().getClassLoader().getResource("validTestRunScriptWithParamJKS.xml").getFile());

        final CredMaServiceApiController serviceController = new CredMaServiceApiControllerImpl();
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(pathFromResource);
        final List<Actions> ListActionToDo = serviceController.checkActionToPerform(appClientConfig, true);

        // Test ActionList
        assertTrue("List Action should have one element", ListActionToDo.size() == 2);

        final CommandCheck cmd = new CommandCheck(pathFromResource, true);

        File f = new File("testScript1");

        cmd.runScriptAction(ListActionToDo.get(0));
        assertTrue("Script1 should have to create testScript1", f.exists());

        cmd.runScriptAction(ListActionToDo.get(1));
        assertTrue("Script2 should have to delete testScript1", !f.exists());

        // Test postScript
        f = new File("testScript2");
        pathFromResource = new File(this.getClass().getClassLoader().getResource("validTestRunScriptWithParamJKS.xml").getFile());

        CommandInstall postScriptCmd = new CommandInstall(pathFromResource);
        postScriptCmd.execute();
        assertTrue("Script1 should have to create testScript2", f.exists());

        pathFromResource = new File(this.getClass().getClassLoader().getResource("validTestRunScript2WithParamJKS.xml").getFile());
        postScriptCmd = new CommandInstall(pathFromResource);
        postScriptCmd.execute();

        assertTrue("Script1 should have to delete testScript2", !f.exists());
    }

    @Test
    public void testActionRunScriptForTrustOnly() throws NamingException, ParseException, JAXBException, SAXException {
        File pathFromResource = new File(this.getClass().getClassLoader().getResource("validTestRunScriptForTrustOnlyJKS.xml").getFile());

        final CredMaServiceApiController serviceController = new CredMaServiceApiControllerImpl();
        final ApplicationCertificateConfigInformation appClientConfig = ApplicationCertificateConfigFactory.getInstance(pathFromResource);
        final List<Actions> ListActionToDo = serviceController.checkActionToPerform(appClientConfig, true);

        // Test ActionList
        assertTrue("List Action should have one element", ListActionToDo.size() == 1);

        final CommandCheck cmd = new CommandCheck(pathFromResource, true);

        final File f1 = new File("testScript1");

        cmd.runScriptAction(ListActionToDo.get(0));
        assertTrue("Script1 should have to create testScript1", f1.exists());

        // Test postScript
        final File f2 = new File("testScript2");
        pathFromResource = new File(this.getClass().getClassLoader().getResource("validTestRunScriptForTrustOnlyJKS.xml").getFile());

        final CommandInstall postScriptCmd = new CommandInstall(pathFromResource);
        postScriptCmd.execute();
        assertTrue("Script1 should have to create testScript2", f2.exists());

        // delete files
        f1.delete();
        f2.delete();
    }
    
    @Before
    public void copyScriptInLocation() {

        final String path1 = this.getClass().getClassLoader().getResource("testScript1.sh").getPath();
        final String path2 = this.getClass().getClassLoader().getResource("testScript2.sh").getPath();
        final List<String> shCmd = new ArrayList<String>();

        shCmd.clear();
        shCmd.add("cp");
        shCmd.add(path1);
        shCmd.add("/tmp");
        try {
            final ProcessBuilder pb = new ProcessBuilder(shCmd);
            final Process p = pb.start();
            p.waitFor();
        } catch (final Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        shCmd.clear();
        shCmd.add("cp");
        shCmd.add(path2);
        shCmd.add("/tmp");
        try {
            final ProcessBuilder pb = new ProcessBuilder(shCmd);
            final Process p = pb.start();
            p.waitFor();
        } catch (final Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        File file = new File("/tmp/testScript1.sh");
        file.setExecutable(true);
        file.setReadable(true);
        file.setWritable(true);
        file = new File("/tmp/testScript2.sh");
        file.setExecutable(true);
        file.setReadable(true);
        file.setWritable(true);
    }

    @After
    public void removeScriptFromLocation() {

        final List<String> shCmd = new ArrayList<String>();

        shCmd.clear();
        shCmd.add("rm");
        shCmd.add("-rf");
        shCmd.add("/tmp/testScript1.sh");
        try {
            final ProcessBuilder pb = new ProcessBuilder(shCmd);
            final Process p = pb.start();
            p.waitFor();
        } catch (final Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        shCmd.clear();
        shCmd.add("rm");
        shCmd.add("-rf");
        shCmd.add("/tmp/testScript2.sh");
        try {
            final ProcessBuilder pb = new ProcessBuilder(shCmd);
            final Process p = pb.start();
            p.waitFor();
        } catch (final Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
    @Test
    public void testActionlist() {
        ActionListManager clMng = new ActionListManager();
        assertTrue(clMng.isEmpty());
        clMng.addAction(new Actions());
        assertTrue(clMng.size() == 1);
        List<Actions> actions = new ArrayList<Actions>();
        Actions a1 = new Actions();
        a1.setAction(CredentialManagerActionEnum.RUN_SCRIPT);
        a1.setCommand(new CredentialManagerCommandType());
        Actions a2 = new Actions();
        actions.add(a1);
        actions.add(a2);
        clMng.setActions(null);
        assertTrue(clMng.size() == 1);
        clMng.setActions(actions);
        assertTrue(clMng.size() == 2);
        clMng.clearActionsList();
        assertTrue(clMng.size() == 0);
        clMng.addAction(new Actions());
        clMng.setAddActions(null);
        assertTrue(clMng.size() == 1);
        List<Actions> actions2 = new ArrayList<Actions>();
        actions2.add(a1);
        actions2.add(a2);
        clMng.setAddActions(actions2);
        assertTrue(clMng.size() == 3);
        //actions equals test
        Actions a3 = new Actions();
        Actions a4 = new Actions();
        assertTrue(a3.equals(a3));
        assertTrue(!a3.equals(null));
        assertTrue(!a3.equals("string"));
        assertTrue(a3.equals(a4));
        //action
        a4.setAction(CredentialManagerActionEnum.RUN_SCRIPT);
        assertTrue(!a3.equals(a4));
        a4.setAction(null);
        a3.setAction(CredentialManagerActionEnum.VM_RESTART);
        assertTrue(!a3.equals(a4));
        a4.setAction(CredentialManagerActionEnum.VM_RESTART);
        //CommandType
        a3.setCommand(new CredentialManagerCommandType());
        assertTrue(!a3.equals(a4));
        a3.setCommand(null);
        a4.setCommand(new CredentialManagerCommandType());
        assertTrue(!a3.equals(a4));
        a3.setCommand(new CredentialManagerCommandType());
        assertTrue(a3.equals(a4));
        CredentialManagerCommandType c3 = new CredentialManagerCommandType();
        CredentialManagerCommandType c4 = new CredentialManagerCommandType();
        a3.setCommand(c3);
        a4.setCommand(c4);
        c3.addPathname("path3.1");
        assertTrue(!a3.equals(a4));
        c4.addPathname("path4.1");
        assertTrue(!a3.equals(a4));
        c4.getPathname().clear();
        c4.addPathname("path3.1");
        assertTrue(a3.equals(a4));
        a3.getCommand().addParameterName("par3.1");
        a3.getCommand().addParameterValue("value3.1");
        assertTrue(!a3.equals(a4));
        a4.getCommand().addParameterName("par4.1");
        assertTrue(!a3.equals(a4));
        a4.getCommand().getParameterName().clear();
        a4.getCommand().addParameterName("par3.1");
        a4.getCommand().addParameterValue("value4.1");
        assertTrue(!a3.equals(a4));
        a4.getCommand().getParameterValue().clear();
        a4.getCommand().addParameterValue("value3.1");
        assertTrue(a3.equals(a4));
    }
    
    @Test
    public void CreateActionElementTest() {
        CheckResult res = new CheckResult(); //all false
        List<CredentialManagerCheckAction> cmCheck = new ArrayList<CredentialManagerCheckAction>();
        List<Actions> out = CreateActionElement.parseActionList(res, cmCheck);
        assertTrue(out.isEmpty());
        res.setResult("trustUpdate", true);
        cmCheck.add(new CredentialManagerCheckActionImpl(new CheckActionType()));
        CheckActionType cat = new CheckActionType();
        ActionType at = ActionType.RUN_SCRIPT;
        cat.setAction(at);
        CommandType ct = new CommandType();
        ParameterType pt = new ParameterType();
        pt.setName("par");
        pt.setValue("val");
        ct.getParameter().add(pt);
        ct.getPathname().add("/tmp/");
        cat.setCommand(ct);
        cat.getCheckcause().add(ActionCauseType.CRL_UPDATE);
        cat.getCheckcause().add(ActionCauseType.TRUST_UPDATE);
        cmCheck.add(new CredentialManagerCheckActionImpl(cat));
        cmCheck.add(new CredentialManagerCheckActionImpl(cat));
        out = CreateActionElement.parseActionList(res, cmCheck);
        assertTrue(out.size() == 1);
        
    }
    
} // end of TestCheckActionToPerform
