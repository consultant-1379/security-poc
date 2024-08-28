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

import javax.naming.NamingException;

import org.apache.commons.cli.ParseException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credentialmanager.cli.business.ExecuteCommandsImpl;

//TODO to refactor the tests.
@RunWith(JUnit4.class)
public class CommandsTest {

    @Test
    public void testUnrecognizedCommandOptions() throws NamingException, ParseException, IOException {
        final String[] commands = (("-b -c -d -x c:\\xml -f -i")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Unrecognized option: -b") > -1);
        }
    }

    @Test
    public void testUnrecognizedCommandOptionsWithoutHyphen() throws NamingException, ParseException, IOException {
        final String[] commands = (("kkk")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Unrecognized option: kkk") > -1);
        }
    }

    @Test
    public void testUseHelpCommand() throws NamingException, ParseException, IOException {
        final String[] commands = (("-h")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        assertEquals("Should return 0 if ok and print the help command", 0, new ExecuteCommandsImpl().execute(commands));
    }

    @Test
    public void testXMLDoNotExists() {
        final String[] commands = (("-i -x xxx.xml")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("xxx.xml") > -1);
        }
    }

//    @Test
//    public void testXMLDoNotExistsWithReset() {
//        final String[] commands = (("-i -r -x xxx.xml")).split(" ");
//        //final CLIProcessor cli = new CLIProcessor();
//        try {
//            new ExecuteCommandsImpl().execute(commands);
//        } catch (final Exception e) {
//            assertTrue(e.getMessage().indexOf("xxx.xml") > -1);
//        }
//    }
    
//    @Test
//    public void testInvalidSequenceOfCommandsInstall() {
//        final String[] commands = (("-i -f xxx.xml")).split(" ");
//        //final CLIProcessor cli = new CLIProcessor();
//        try {
//            new ExecuteCommandsImpl().execute(commands);
//        } catch (final Exception e) {
//            assertTrue(e.getMessage().indexOf("Invalid use of options:") > -1);
//        }
//    }

    @Test
    public void testInvalidUseOfOptionsInstall1() {
        final String[] commands = (("-i")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Invalid use of options:") > -1);
        }
    }

    @Test
    public void testInvalidUseOfOptionsInstall2() {
        final String[] commands = (("--install")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Invalid use of options:") > -1);
        }
    }

    @Test
    public void testInvalidUseOfOptionsInstall3() {
        final String[] commands = (("-install")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Invalid use of options:") > -1);
        }
    }

    @Test
    public void testInvalidSequenceOfCommandsList() throws NamingException, ParseException, IOException {
        final String[] commands = (("-h -i xxx.xml")).split(" ");
        //final CLIProcessor cli = new CLIProcessor();
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Invalid use of options:") > -1);
        }
    }

    @Rule
    public TemporaryFolder folder = new TemporaryFolder();

    @Test
    public void testXMLExists() throws IOException, NamingException, ParseException {
        // File createdFolder = folder.newFolder("teste");
        // folder.create();
        final File createdFile = this.folder.newFile("teste.xml");
        this.folder.create();

        assertTrue("Should return true if the file could be created", createdFile.exists());
        final String[] commands = (("-i -x " + createdFile.getAbsolutePath())).split(" ");
        //final CLIProcessor cli = new CLIProcessor();

        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Premature end of file.") > -1);
        }
    }
    
    @Test
    public void testXMLCheckExists() throws IOException, NamingException, ParseException {
        final File createdFile = this.folder.newFile("testeCheck.xml");
        this.folder.create();

        assertTrue("Should return true if the file could be created", createdFile.exists());
        final String[] commands = (("-c -x " + createdFile.getAbsolutePath())).split(" ");

        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Premature end of file.") > -1);
        }
    }


    @Test
    public void testDailyRunOptionParse() {
        final String[] commands = (("-c -d -p /tmp/xx")).split(" ");
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("/tmp/xx") > -1);
        }
    }

    @Test
    public void testPathXMLDoNotExists() {
        final String[] commands = (("-c -p /tmp/xx")).split(" ");
        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("/tmp/xx") > -1);
        }
    }
    
    @Test
    public void testPathXMLExists() throws IOException, NamingException, ParseException {
        final File createdFile = this.folder.newFile("teste.xml");
        this.folder.create();

        assertTrue("Should return true if the file could be created", createdFile.exists());
        final String[] commands = (("-c -p " + this.folder.getRoot())).split(" ");

        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Premature end of file.") > -1);
        }
    }
    
    @Test
    public void testPathInstallXMLExists() throws IOException, NamingException, ParseException {
        final File createdFile = this.folder.newFile("testeInstall.xml");
        this.folder.create();

        assertTrue("Should return true if the file could be created", createdFile.exists());
        final String[] commands = (("-i -p " + this.folder.getRoot())).split(" ");

        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Premature end of file.") > -1);
        }
    }
    
    @Test
    public void testPathInstallXExists() throws IOException, NamingException, ParseException {
        final File createdFile = this.folder.newFile("testXinstallPatch.xml");
        this.folder.create();

        assertTrue("Should return true if the file could be created", createdFile.exists());
        final String[] commands = (("-i -x " + this.folder.getRoot())).split(" ");

        try {
            new ExecuteCommandsImpl().execute(commands);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Premature end of file.") > -1);
        }
    }
    
    @Test
    public void testInvalidUseOfOptionsCheck() {
        final String[] commands = (("-c ")).split(" ");
        try {
            new ExecuteCommandsImpl().execute(commands);
            assertTrue(false);
        } catch (final Exception e) {
            assertTrue(e.getMessage().indexOf("Invalid use of options:") > -1);
        }
    }
    
    @Test
    public void testVersion() {
        final String[] commands = (("-v ")).split(" ");
        try {
            new ExecuteCommandsImpl().execute(commands);
            assertTrue(true);
        } catch (final Exception e) {
            assertTrue(false);
        } 
    }

}
