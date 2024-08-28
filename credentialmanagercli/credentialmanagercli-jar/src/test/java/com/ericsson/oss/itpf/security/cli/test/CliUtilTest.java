package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.util.CheckResult;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.FileSearch;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;

public class CliUtilTest {
    
       
    @Test
    public void LoggerTest() {
        assertNotNull(Logger.getLogger());
        assertNotNull(Logger.getLogger());
    }
    
    @Test
    public void FileSearchTest() throws Exception {
        assertNotNull(FileSearch.getFile("/fakedir/fakeFile1"));
    }
    
    @Test
    public void CheckResultTest() {
        CheckResult cr = new CheckResult();
        cr.setResult("notExistingCause", true);
        assertTrue(cr.isAllFalse());
        cr.setResult("certificateUpdate", true);
        assertTrue(!cr.isAllFalse());
        cr.setResult("certificateUpdate", false);
        cr.setResult("trustUpdate", true);
        assertTrue(!cr.isAllFalse());
        cr.setResult("trustUpdate", false);
        cr.setResult("crlUpdate", true);
        assertTrue(!cr.isAllFalse());
        cr.setResult("trustUpdate", true);
        assertTrue(!cr.isAllFalse());
        cr.setResult("trustUpdate", false);
        cr.setResult("certificateUpdate", true);
        assertTrue(!cr.isAllFalse());
        cr.setResult("trustUpdate", true);
        assertTrue(!cr.isAllFalse());
        cr.setResult("crlUpdate", false);
        assertTrue(!cr.isAllFalse());
    }
}
