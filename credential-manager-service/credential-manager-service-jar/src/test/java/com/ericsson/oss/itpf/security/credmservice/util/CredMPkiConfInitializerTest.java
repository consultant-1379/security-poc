package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.*;

import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.credmservice.api.PKIDbFactory;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.exceptions.*;
import com.ericsson.oss.itpf.security.credmservice.logging.api.SystemRecorderWrapper;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.custom.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;

@RunWith(MockitoJUnitRunner.class)
public class CredMPkiConfInitializerTest {

    @Rule
    public TemporaryFolder testFolder = new TemporaryFolder();

    @Mock
    PKIDbFactory mockDbFactory;
    @Mock
    SystemRecorderWrapper sysRec;

    @InjectMocks
    CredMPkiConfInitializer credmPkiConfInit;

    @Test
    public void upgradeFail() {

        try {
            this.credmPkiConfInit.upgrade();
            assertTrue(false);
        } catch (final CredentialManagerDbUpgradeException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testCatDbConf() throws IOException {

        final File catFile = testFolder.newFile("PKICategories.xml");

        Method catConf = null;
        try {
            catConf = CredMPkiConfInitializer.class.getDeclaredMethod("pkiCatDbConf", File.class);
            catConf.setAccessible(true);
        } catch (IllegalArgumentException | NoSuchMethodException | SecurityException e) {
            assertTrue(false);
        }

        try {
            catConf.invoke(credmPkiConfInit, catFile);
            assertTrue(false);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(true);
        }

        PrintWriter printWr = null;
        try {
            printWr = new PrintWriter(catFile.getAbsolutePath());
        } catch (final FileNotFoundException e1) {
            assertTrue(false);
        }
        printWr.println("<?xml version='1.0' encoding='UTF-8'?>");
        printWr.println(
                "<EndEntityCategories xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' xsi:noNamespaceSchemaLocation='CategoriesSchema.xsd'>");
        printWr.println("<undefinedCategoryName>UNDEFINED</undefinedCategoryName>");
        printWr.println("<serviceCategoryName>SERVICE</serviceCategoryName>");
        printWr.println("<categoryNameList>CATEGORY</categoryNameList>");
        printWr.println("</EndEntityCategories>");
        printWr.close();

        try {
            catConf.invoke(credmPkiConfInit, catFile);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            catFile.delete();
            assertTrue(false);
        }

        try {
            Mockito.doThrow(new PkiCategoryMapperException()).when(mockDbFactory).pkiCategoryDbConf(Matchers.any(AppCategoryXmlConfiguration.class));
        } catch (final PkiCategoryMapperException e1) {
            catFile.delete();
            assertTrue(false);
        }
        try {
            catConf.invoke(credmPkiConfInit, catFile);
            catFile.delete();
            assertTrue(false);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(true);
        }
    }

    @Test
    public void testPkiDbConf() {

        final File enmInit = new File("/tmp/enmInit");
        enmInit.mkdir();
        final File entitiesFile = new File(enmInit + "/Entities");
        entitiesFile.mkdir();
        final File profilesFile = new File(enmInit + "/Profiles");
        profilesFile.mkdir();
        final File enmTree = new File(enmInit + "/ENM_sub");
        enmTree.mkdir();
        final File entity = new File(entitiesFile + "/entity1.xml");
        try {
            entity.createNewFile();
        } catch (final IOException e1) {
            assertTrue(false);
        }
        final File profile = new File(profilesFile + "/profile1.xml");
        try {
            profile.createNewFile();
        } catch (final IOException e1) {
            assertTrue(false);
        }

        Method dbConf = null;
        try {
            dbConf = CredMPkiConfInitializer.class.getDeclaredMethod("pkiDbConf", File.class);
            dbConf.setAccessible(true);
        } catch (IllegalArgumentException | NoSuchMethodException | SecurityException e) {
            assertTrue(false);
        }

        try {
            dbConf.invoke(credmPkiConfInit, enmInit);
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(true);
        }

        try {
            final FileChannel caEntCHIn = new FileInputStream("src/test/resources/caEntities.xml").getChannel();
            final FileChannel caEntCHOut = new FileOutputStream(entity).getChannel();
            caEntCHOut.transferFrom(caEntCHIn, 0, caEntCHIn.size());

            if (caEntCHIn != null) {
                caEntCHIn.close();
            }
            if (caEntCHOut != null) {
                caEntCHOut.close();
            }
        } catch (final IOException e) {
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        }
        try {
            dbConf.invoke(credmPkiConfInit, enmInit);
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(true);
        }

        //valid profiles.xml

        try {
            final FileChannel caProfCHIn = new FileInputStream("src/test/resources/certificateProfile.xml").getChannel();
            final FileChannel caProfCHOut = new FileOutputStream(profile).getChannel();
            caProfCHOut.transferFrom(caProfCHIn, 0, caProfCHIn.size());

            if (caProfCHIn != null) {
                caProfCHIn.close();
            }
            if (caProfCHOut != null) {
                caProfCHOut.close();
            }
        } catch (final IOException e) {
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        }
        try {
            dbConf.invoke(credmPkiConfInit, enmInit);
            assertTrue(true);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        }

        //Exceptions ///////

        try {
            Mockito.doThrow(new PkiProfileMapperException()).when(mockDbFactory).PKIDbConf(Matchers.anyList(), Matchers.anyList());
        } catch (CertificateExtensionException | InvalidSubjectException | MissingMandatoryFieldException | UnSupportedCertificateVersion
                | CANotFoundException | AlgorithmNotFoundException | EntityCategoryNotFoundException | InvalidCAException
                | InvalidEntityCategoryException | CertificateGenerationException | CertificateServiceException | ExpiredCertificateException
                | RevokedCertificateException | ProfileServiceException | EntityServiceException | ProfileNotFoundException | EntityNotFoundException
                | InvalidProfileAttributeException | ProfileAlreadyExistsException | EntityAlreadyExistsException | InvalidEntityAttributeException
                | InvalidProfileException | UnsupportedCRLVersionException | CRLExtensionException | InvalidCRLGenerationInfoException
                | PkiProfileMapperException | PkiEntityMapperException | IOException | InvalidEntityException | CRLGenerationException e1) {
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        }

        try {
            dbConf.invoke(credmPkiConfInit, enmInit);
            this.deleteAllCADirs(enmInit);
            assertTrue(false);
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(true);
        }

        this.deleteAllCADirs(enmInit);

    }

    @Test
    public void malformedFileTest() {

        try {
            credmPkiConfInit.getEntitiesConf(new File("src/test/resources/ENM-Root-CA/ENM-Sub1-CA/ENM-Sub2-CA/ENM-END-ENTITIES/Entities"));
            assertTrue(false);
        } catch (final CredentialManagerEntitiesException e) {
            assertTrue(true);
        }

    }

    @Test
    public void testCheckDbCvnStatus()
            throws CustomConfigurationNotFoundException, CustomConfigurationInvalidException, CustomConfigurationServiceException {
        Mockito.when(mockDbFactory.readAndCheckCvn()).thenReturn(true);
        this.credmPkiConfInit.checkDbCvnStatus();
        Mockito.when(mockDbFactory.readAndCheckCvn()).thenReturn(false);
        this.credmPkiConfInit.checkDbCvnStatus();
    }

    private void deleteAllCADirs(final File enmInit) {
        for (final File temp : enmInit.listFiles()) {
            if (temp.isDirectory()) {
                for (final File subTemp : temp.listFiles()) {
                    assertTrue(subTemp.delete());
                }
            }
            assertTrue(temp.delete());
        }
        assertTrue(enmInit.delete());
    }
}
