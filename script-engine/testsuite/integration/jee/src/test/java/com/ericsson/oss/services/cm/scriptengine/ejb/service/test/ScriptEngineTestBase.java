/*------------------------------------------------------------------------------
*******************************************************************************
* COPYRIGHT Ericsson 2016
*
* The copyright to the computer program(s) herein is the property of
* Ericsson Inc. The programs may be used and/or copied only with written
* permission from Ericsson Inc. or in accordance with the terms and
* conditions stipulated in the agreement/contract under which the
* program(s) have been supplied.
*******************************************************************************
*----------------------------------------------------------------------------*/

package com.ericsson.oss.services.cm.scriptengine.ejb.service.test;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import org.jboss.arquillian.container.test.api.ContainerController;
import org.jboss.arquillian.container.test.api.Deployer;
import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.arquillian.container.test.api.TargetsContainer;
import org.jboss.arquillian.junit.InSequence;
import org.jboss.arquillian.test.api.ArquillianResource;
import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.ericsson.oss.services.cm.scriptengine.ejb.service.test.Artifact.BEANS_XML_FILE;
import static com.ericsson.oss.services.cm.scriptengine.ejb.service.test.Artifact.MANIFEST_FM_FILE;
import static com.ericsson.oss.services.cm.scriptengine.ejb.service.test.Artifact.addEarRequiredlibraries;
import static com.ericsson.oss.services.cm.scriptengine.ejb.service.test.Artifact.createJarModuleArchive;


public abstract class ScriptEngineTestBase {

    protected static final String EAP7_DEPLOYMENT = "CmScriptEngineTest";
    protected static final String EAP7_SERVER = "jboss_managed";
    private static final Logger logger = LoggerFactory.getLogger(ScriptEngineTestBase.class);

    @ArquillianResource
    private static ContainerController controller;

    @ArquillianResource
    private static Deployer deployer;

    @Deployment(name = EAP7_DEPLOYMENT, managed = false)
    @TargetsContainer(EAP7_SERVER)
    public static Archive<EnterpriseArchive> createTestArchive() {
        logger.info("Creating deployment: script-engine-test.ear");
        final EnterpriseArchive ear = ShrinkWrap.create(EnterpriseArchive.class, "script-engine-test.ear");
        addEarRequiredlibraries(ear);
        ear.addAsModule(createJarModuleArchive());
        ear.setManifest(MANIFEST_FM_FILE);
        ear.addAsApplicationResource(BEANS_XML_FILE);
        return ear;
    }

    @Test
    @InSequence(0)
    public void setupEAP7() { //workaround for a deployment issue - delay EAR deployment until JBOSS has started
        File deploymentsDir = Paths.get(System.getProperty("jboss.home"), "standalone", "deployments").toFile();

        File[] ears = deploymentsDir.listFiles(pathname -> pathname.getName().endsWith("ear"));

        List<File> skippedEARs = new ArrayList<>();
        for(File f : ears) {
            String path = f.toString()+".skipdeploy";
            File f1 = new File(path);
            try {
                assert(f1.createNewFile());
                skippedEARs.add(f1);
            } catch (IOException e) {
                logger.error("failed to create a skipDeploy file", e);
            }
        }
        logger.info(" script-engine test is starting JBoss EAP7 in manual mode");
        controller.start(EAP7_SERVER);

        for(File f : skippedEARs){
            try {
                Files.delete(f.toPath());
            } catch (IOException e) {
                logger.error(e.getMessage());
            }
        }

        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            logger.error(e.getMessage());
            Thread.currentThread().interrupt();
        }
        logger.info(" script-engine test is deploying script-engine-test.ear");
        deployer.deploy(EAP7_DEPLOYMENT);
        logger.info("setupEAP7 exiting");
    }

    @Rule
    public TestRule watcher = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            logger.info("*******************************");
            logger.info("Starting test: {}()", description.getMethodName());
        }

        @Override
        protected void finished(final Description description) {
            logger.info("Ending test: {}()", description.getMethodName());
            logger.info("*******************************");
        }
    };

    public void asAuthorizedUser() {
        setupUser("authorized_user");
    }

    public void asUnauthorizedUser() {
        setupUser("unauthorized_user");
    }

    // method to setup a different user for RBAC tests
    protected void setupUser(final String user) {
        String tmpDir;
        final String osName = System.getProperty("os.name");
        if (osName.equals("Linux")) {
            tmpDir = "/tmp";
        } else {
            tmpDir = System.getProperty("java.io.tmpdir");
        }

        try (FileWriter fw = new FileWriter(new File(tmpDir, "currentAuthUser"))) {
            fw.write(user);
        } catch (final IOException e) {
            logger.info("setupUser IOException: {}", e.getMessage());
        }
    }
}