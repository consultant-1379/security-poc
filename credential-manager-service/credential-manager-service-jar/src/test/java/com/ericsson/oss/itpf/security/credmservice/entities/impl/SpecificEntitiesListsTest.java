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
import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;

public class SpecificEntitiesListsTest {

    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.entities.impl.SpecificEntitiesLists#splitIntoSpecificLists(java.util.List)}
     * .
     */

    private List<AppEntityXmlConfiguration> prepareEntities() {

        final List<AppEntityXmlConfiguration> appEntXConfList = new ArrayList<AppEntityXmlConfiguration>();

        AppEntityXmlConfiguration entityConfigInfo1 = null;
        AppEntityXmlConfiguration entityConfigInfo2 = null;

        final File xmlPathTest1 = new File("src/test/resources/endEntities.xml");
        final File xmlPathTest2 = new File("src/test/resources/caEntities.xml");

        try {
            entityConfigInfo1 = new AppEntityXmlConfiguration(xmlPathTest1);
            entityConfigInfo2 = new AppEntityXmlConfiguration(xmlPathTest2);

            appEntXConfList.add(entityConfigInfo1);
            appEntXConfList.add(entityConfigInfo2);

        } catch (final CredentialManagerEntitiesException e) {
            e.printStackTrace();
        }

        return appEntXConfList;
    }

    @Test
    public void testSplitIntoSpecificLists() {

        final SpecificEntitiesLists genericEntitiesList = new SpecificEntitiesLists();

        genericEntitiesList.splitIntoSpecificLists(prepareEntities());

        assertTrue("CAentity List EMPTY", !genericEntitiesList.getCAentitiesList().isEmpty());

        assertTrue("Entity List EMPTY", !genericEntitiesList.getEntitiesList().isEmpty());

    }
}
