package com.ericsson.oss.itpf.security.credmservice.impl;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlEntityProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.profiles.impl.AppProfileXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.util.CredMPkiConfInitializer;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

@RunWith(MockitoJUnitRunner.class)
public class CredMPkiConfTest {

    @Mock
    PKIDbFactory pKIDbFactory;

    //CredMPkiConfInitializer conf = new CredMPkiConfInitializer();
    @InjectMocks
    CredMPkiConfInitializer conf;

    final Properties prop = PropertiesReader.getConfigProperties();

    // scan empty directories tree to verify recursion works fine
    //@Test
    //public void recursionTest() {
    //conf.first();

    //   assertTrue(conf.getAppEntXConfList().size() == 0);
    //   assertTrue(conf.getAppProfXConfList().size() == 0);
    // }

    @Test
    public void getEntitiesTest() {

        final File dirEntities = new File(prop.getProperty("path.xml.test.getEntities"));

        conf.getAppEntXConfList().clear();

        try {
            conf.getEntitiesConf(dirEntities);
        } catch (final CredentialManagerEntitiesException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            assertTrue(false);
        }

        assertTrue(conf.getAppEntXConfList().size() == 1);

        final AppEntityXmlConfiguration appEntityXmlConfiguration = conf.getAppEntXConfList().get(0);

        final List<XmlCAEntity> xmlCaEntityList = appEntityXmlConfiguration.getCAEntitiesInfo();

        assertTrue(xmlCaEntityList.get(0).getSubject().getSubjectDN().getSubjectEntry().get(0).getValue().toString().equals("NE External CA"));

        conf.getAppEntXConfList().clear();

    }

    @Test
    public void getProfilesTest() {

        final File dirProfiles = new File(prop.getProperty("path.xml.test.getProfiles"));

        conf.getAppProfXConfList().clear();

        try {
            conf.getProfilesConf(dirProfiles);
        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
            assertTrue(false);
        }

        assertTrue(conf.getAppProfXConfList().size() == 2);

        final AppProfileXmlConfiguration appProfileXmlConfiguration = conf.getAppProfXConfList().get(0);

        final List<XmlEntityProfile> xmlEntityProfileList = appProfileXmlConfiguration.getEntityProfilesInfo();

        final List<XmlCertificateProfile> xmlCerticateProfileList = appProfileXmlConfiguration.getCertificateProfilesInfo();

        final int sizeXmlEntityProfileList = xmlEntityProfileList.size();

        if (sizeXmlEntityProfileList != 0) {

            assertTrue(xmlEntityProfileList.get(0).getCertificateProfileName().toString().equals("NE CA CP"));

        } else {
            assertTrue(xmlCerticateProfileList.get(0).getName().toString().equals("ENM CA CP"));
        }

        conf.getAppProfXConfList().clear();

    }

    @Test
    public void findDirectoriesTest() {

        final File dirParent = new File(prop.getProperty("path.xml.test"));

        final File[] childDirectories = conf.findDirectories(dirParent);

        assertTrue(childDirectories.length == 2);

        final List<String> expected = Arrays.asList("src/test/resources/ENM-Sub1-CA/Entities", "src/test/resources/ENM-Sub1-CA/Profiles");
        final List<String> actual = Arrays.asList(childDirectories[0].toPath().toString(), childDirectories[1].toPath().toString());

        assertTrue("check equality", expected.containsAll(actual) && actual.containsAll(expected));

    }

    @Test
    public void findFilesTest() {

        final File dir = new File(prop.getProperty("path.xml.test.getFiles"));

        final File[] foundFiles = conf.findFiles(dir);

        assertTrue(foundFiles.length == 1);

    }
}
