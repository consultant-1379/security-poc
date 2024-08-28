package com.ericsson.oss.itpf.security.cli.test;

import java.io.File;

import org.junit.Assert;
import org.junit.Test;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils.HostnameResolveUtil;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.utils.XmlFileFilter;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class ModelUtilsTest {
    
    @Test
    public void HostNameResolveUtilTest1() {
        HostnameResolveUtil hres = new HostnameResolveUtil();
        hres.validateString("CN=entityhostname");
        try {
            hres.validateString("CN=entity##hostname");
            Assert.assertTrue(false);
        } catch(CredentialManagerException e) {
            Assert.assertTrue(true);
        }
        hres.validateString("CN=entity##hostname##");
        try {
            hres.validateString("CN=entity##hoooostname##");
            Assert.assertTrue(false);
        } catch(CredentialManagerException e) {
            Assert.assertTrue(true);
        }
    }
    
    @Test
    public void XmlFileFilterTest() {
        XmlFileFilter name = new XmlFileFilter();
        File file = new File("file.xml");
        File file1 = new File("xml.file");
        Assert.assertTrue(name.accept(file));
        Assert.assertTrue(!name.accept(file1));
        Assert.assertTrue(!name.acceptXml(file1));
        Assert.assertTrue(name.acceptXml(file));
    }
}
