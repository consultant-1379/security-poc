/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.itpf.security.pki.cmdhandler.util;

import static org.junit.Assert.*;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse.PKICommandResponseType;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiMessageCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;

@RunWith(MockitoJUnitRunner.class)
public class CliUtilTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(CliUtil.class);

    @InjectMocks
    CliUtil cliUtil;

    Map<String, Object> propMap;

    @Mock
    ExportedItemsHolder exportedItemsHolder;

    @Before
    public void setup() throws IOException, URISyntaxException {
        MockitoAnnotations.initMocks(this);
        propMap = new HashMap<String, Object>();
        URL url = getClass().getClassLoader().getResource("Entityprofiles.xml");
        propMap.put("filePath", url.getPath());
    }

    @Test(expected = CommandSyntaxException.class)
    public void testGetFileContentFromCommandPropertiesFilePathNull() throws IOException {
        MockitoAnnotations.initMocks(cliUtil);
        propMap = new HashMap<String, Object>();
        propMap.put("filePath", null);
        String d = cliUtil.getFileContentFromCommandProperties(propMap);
        assertFalse(d.equalsIgnoreCase("failed"));
    }

    @Test
    public void testGetFileContentFromCommandPropertiesSuccess() {
        CliUtil cliUtil = new CliUtil();
        String d = cliUtil.getFileContentFromCommandProperties(propMap);
        assertTrue(d.contains("RootCA_Entity_Profile"));
    }

    @Test
    public void testGetFileContentFromCommandPropertiesFailure() {
        CliUtil cliUtil = new CliUtil();
        String d = cliUtil.getFileContentFromCommandProperties(propMap);
        assertFalse(d.equalsIgnoreCase("failed"));
    }

    @Test(expected = CommandSyntaxException.class)
    public void testGetFileContentFromCommandPropertiesEmptyContent() throws IOException {
        MockitoAnnotations.initMocks(cliUtil);
        propMap = new HashMap<String, Object>();
        URL url = getClass().getClassLoader().getResource("emptyfile.txt");
        propMap.put("filePath", url.getPath());
        String d = cliUtil.getFileContentFromCommandProperties(propMap);
        assertFalse(d.equalsIgnoreCase("failed"));
    }

    @Test(expected = CommandSyntaxException.class)
    public void testGetFileContentFromCommandPropertiesIO() throws IOException {
        MockitoAnnotations.initMocks(cliUtil);
        propMap = new HashMap<String, Object>();
        URL url = new URL("file:he");
        propMap.put("filePath", url.getPath().replaceFirst("/", ""));
        String d = cliUtil.getFileContentFromCommandProperties(propMap);
        assertFalse(d.equalsIgnoreCase("failed"));
    }

    @Test
    public void testGenerateKey() {
        String id = CliUtil.generateKey();
        Assert.assertTrue(id.contains("_"));
    }

    @Test
    public void testStringNullOrEmpty() {
        assertTrue(cliUtil.isNullOrEmpty(""));
        String nullstring = null;
        assertTrue(cliUtil.isNullOrEmpty(nullstring));
    }

    @Test
    public void testGetFileBytesFromCommandProperties() {
        byte[] bytes = cliUtil.getFileBytesFromCommandProperties(propMap);
        assertNotNull(bytes);
    }

    @Test(expected = CommandSyntaxException.class)
    public void testGetFileBytesFromCommandPropertiesException() {
        propMap.put("filePath", null);
        byte[] bytes = cliUtil.getFileBytesFromCommandProperties(propMap);
        assertNotNull(bytes);
    }

    @Test
    public void testPrepareErrorMessage() {
        PkiMessageCommandResponse pkiCommandResponse = (PkiMessageCommandResponse) cliUtil.prepareErrorMessage(0, Constants.CA_ENTITY_GOT_UPDATED_SUCCESSFULLY, null);
        assertTrue(pkiCommandResponse.getMessage().contains(Constants.CA_ENTITY_GOT_UPDATED_SUCCESSFULLY));
    }

    @Test
    public void testSplitBySeprator() {
        List<String> stringList = cliUtil.splitBySeparator("sfd,sd", Constants.COMMA);
        assertTrue(stringList.get(0).contains("sfd"));
    }

    @Test
    public void splitBySeprator() {
        List<String> stringList = cliUtil.splitBySeprator("sfd,sd", Constants.COMMA);
        assertTrue(stringList.get(0).contains("sfd"));
    }

    @Test
    public void testBuildPkiCommandResponse() {
        Mockito.doNothing().when(exportedItemsHolder).save(CliUtil.generateKey(), new DownloadFileHolder());
        PkiCommandResponse pkiCommandResponse = cliUtil.buildPkiCommandResponse("", "application", "".getBytes());
        assertEquals(PKICommandResponseType.DOWNLOAD_REQ, pkiCommandResponse.getResponseType());
    }

}
