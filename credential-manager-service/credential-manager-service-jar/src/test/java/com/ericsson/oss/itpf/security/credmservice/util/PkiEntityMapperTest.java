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
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.File;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.entities.api.EntityConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

public class PkiEntityMapperTest {

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.credmservice.util.PkiEntityMapper#ConvertEntityFrom(com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEntity)}
     * .
     */
    @Test
    public void testConvertEntityFrom() {

        final File xmlPathTest = new File("src/test/resources/endEntities.xml");

        EntityConfigInformation entityConfigInfo = null;

        try {
            entityConfigInfo = new AppEntityXmlConfiguration(xmlPathTest);
        } catch (final CredentialManagerEntitiesException e) {

            e.printStackTrace();
        }

        assertTrue("entityConfigInfo is NULL", entityConfigInfo != null);

        Entity entity = null;
        try {
            entity = PkiEntityMapper.ConvertEntityFrom(entityConfigInfo.getEntitiesInfo().get(1));

        } catch (final PkiEntityMapperException e) {

            e.printStackTrace();
        }

        assertTrue("Wrong Entity Name", entity.getEntityInfo().getName().equals("ENM Infrastructure CA"));
        
        assertTrue("Wrong OTP", entity.getEntityInfo().getOTP().equals("changeit"));

        assertTrue("Wrong Subject", entity.getEntityInfo().getSubject().getSubjectFields().get(0).getValue().equals("rootCA"));

    }

}
