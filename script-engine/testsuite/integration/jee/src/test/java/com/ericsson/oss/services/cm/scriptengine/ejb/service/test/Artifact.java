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

import org.jboss.shrinkwrap.api.Archive;
import org.jboss.shrinkwrap.api.ArchivePath;
import org.jboss.shrinkwrap.api.Filter;
import org.jboss.shrinkwrap.api.Filters;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.asset.EmptyAsset;
import org.jboss.shrinkwrap.api.asset.StringAsset;
import org.jboss.shrinkwrap.api.spec.EnterpriseArchive;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration for EAR Deployment for the Arquillian environment.
 *
 * @since 1.0.1.
 */
public final class Artifact {
    public static final File MANIFEST_FM_FILE = new File("src/test/resources/META-INF/MANIFEST.MF");
    public static final File BEANS_XML_FILE = new File("src/test/resources/META-INF/beans.xml");
    private static final Logger logger = LoggerFactory.getLogger(Artifact.class);
    private static final Filter<ArchivePath> NO_TESTS_FILTER = Filters.exclude(".*Test.*");
    private static final Filter<ArchivePath> TOPIC_EVENT_FILTER = Filters.include(".*ProcessTerminatedEvent.*");
    private static final Filter<ArchivePath> RESPONSE_FILTER = Filters.include(".*ResponseDispatcher.*");
    private Artifact() {}

    public static void addEarRequiredlibraries(final EnterpriseArchive archive) {
        logger.debug("Adding libs to ear: {}", archive);

        archive.addAsLibraries(resolveAsFiles("com.ericsson.oss.services.cm","script-engine-api"));
        archive.addAsLibraries(resolveAsFiles("com.ericsson.oss.services.cm","script-engine-editor-spi"));
        archive.addAsLibraries(resolveAsFiles("com.ericsson.oss.services.cli.alias.model", "clialias-jar"));
        archive.addAsLibraries(resolveAsFiles("com.google.guava", "guava"));
        archive.addAsLibraries(resolveAsFiles("com.fasterxml.jackson.core", "jackson-annotations"));
        archive.addAsLibraries(resolveAsFiles("com.fasterxml.jackson.core", "jackson-core"));
        archive.addAsLibraries(resolveAsFiles("com.fasterxml.jackson.core", "jackson-databind"));
        archive.addAsLibraries(resolveAsFiles("org.jboss.resteasy", "resteasy-jaxrs"));
        archive.addAsLibraries(resolveAsFiles("org.mockito", "mockito-core"));
        archive.addAsLibraries(resolveAsFiles("org.apache.commons", "commons-lang3"));
        archive.addAsLibraries(resolveAsFiles("org.apache.commons", "commons-pool2"));
        archive.addAsLibraries(resolveAsFiles("commons-cli", "commons-cli"));
        archive.addAsLibraries(resolveAsFiles("org.mock-server", "mockserver-netty"));
        archive.addAsLibraries(resolveAsFiles("org.apache.httpcomponents", "httpcore"));
        archive.addAsLibraries(resolveAsFiles("org.apache.httpcomponents", "httpclient"));
        archive.addAsLibraries(resolveAsFiles("org.apache.httpcomponents", "httpmime"));
    }

    public static Archive<JavaArchive> createJarModuleArchive() {
        final JavaArchive archive = ShrinkWrap.create(JavaArchive.class, "script-engine-test.jar")
                .addPackage(ScriptEngineTestBase.class.getPackage())
                // spi
                .addPackages(true,TOPIC_EVENT_FILTER, "com.ericsson.enm.cm.router.jms.topic")
                .addPackages(true,RESPONSE_FILTER, "com.ericsson.oss.services.cm.scriptengine.ejb.service")
                // tests
                .addPackages(true, NO_TESTS_FILTER, "com.ericsson.oss.services.cm.scriptengine.ejb.service.test")
                // stubs

                .addPackages(true, NO_TESTS_FILTER, "com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs")
                .addPackages(true, NO_TESTS_FILTER, "com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest")

                // Service framework properties
                .add(new StringAsset("sdk_service_identifier=script-engine-test\nsdk_service_version=1.2.3"),
                        "ServiceFrameworkConfiguration.properties")
                // beans.xml
                .addAsManifestResource(EmptyAsset.INSTANCE, "beans.xml");
        logger.debug("Creating JAR: {}", archive);
        return archive;
    }

    private static File[] resolveAsFiles(final String groupId, final String artifactId) {
        return Maven.resolver().loadPomFromFile("pom.xml").resolve(groupId + ":" + artifactId).withTransitivity().asFile();
    }
}
