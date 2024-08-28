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
package com.ericsson.oss.itpf.security.pki.manager.model.entities;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.CAEntitySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.EntitySetUpData;

/**
 * This class is used to run Junits for Entities objects in different scenarios
 */
public class EntitiesTest extends EqualsTestCase {

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance()
     */
    @Override
    protected Object createInstance() throws ParseException, DatatypeConfigurationException {
        final Entities entities = new Entities();
        final List<CAEntity> cAEntities = new ArrayList<CAEntity>();
        cAEntities.add(new CAEntitySetUpData().getCAEntityForEqual());
        entities.setCAEntities(cAEntities);
        final List<Entity> endEntities = new ArrayList<Entity>();
        endEntities.add(new EntitySetUpData().getEntityForEqual());
        entities.setEntities(endEntities);
        return entities;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() throws ParseException, DatatypeConfigurationException {
        final Entities entities = new Entities();
        final List<CAEntity> cAEntities = new ArrayList<CAEntity>();
        cAEntities.add(new CAEntitySetUpData().getCAEntityForNotEqual());
        entities.setCAEntities(cAEntities);
        final List<Entity> endEntities = new ArrayList<Entity>();
        endEntities.add(new EntitySetUpData().getEntityForNotEqual());
        entities.setEntities(endEntities);
        return entities;
    }

}
