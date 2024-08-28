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
package com.ericsson.oss.itpf.security.credmservice.entities.impl;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.entities.api.EntityConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;

public class AppEntityXmlConfigurationTest {

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration#getEntitiesInfo()} .
     */
    @Test
    public void testGetEntitiesInfo() {

        final File xmlPathTest = new File("src/test/resources/endEntities.xml");

        EntityConfigInformation entityConfigInfo = null;

        try {
            entityConfigInfo = new AppEntityXmlConfiguration(xmlPathTest);
        } catch (final CredentialManagerEntitiesException e) {

            e.printStackTrace();
        }

        assertTrue("entityConfigInfo is NULL", entityConfigInfo != null);

        assertTrue("Size of endEntities.xml is not correct (2)", entityConfigInfo.getEntitiesInfo().size() == 2);

        assertTrue("Profile(1) name not correct", entityConfigInfo.getEntitiesInfo().get(1).getName().equals("ENM Infrastructure CA"));

    }

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration#getCAEntitiesInfo()} .
     */
    @Test
    public void testGetCAEntitiesInfo() {

        final File xmlPathTest = new File("src/test/resources/caEntities.xml");

        EntityConfigInformation entityConfigInfo = null;

        try {
            entityConfigInfo = new AppEntityXmlConfiguration(xmlPathTest);
        } catch (final CredentialManagerEntitiesException e) {

            e.printStackTrace();
        }

        assertTrue("entityConfigInfo is NULL", entityConfigInfo != null);

        assertTrue("Size of caEntities.xml is not correct (3)", entityConfigInfo.getCAEntitiesInfo().size() == 3);

        assertTrue("Profile(1) name not correct", entityConfigInfo.getCAEntitiesInfo().get(0).getName().equals("ENM_PKI_Root_CA"));

        assertTrue("File path not correct", entityConfigInfo.getXmlFilePath().equals("src/test/resources/caEntities.xml"));

    }

}
