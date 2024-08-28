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

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEntity;

public class SpecificEntitiesLists {

    // private static final long serialVersionUID = 0;
    private final List<XmlEntity> entitiesList = new ArrayList<XmlEntity>();
    private final List<XmlCAEntity> cAentitiesList = new ArrayList<XmlCAEntity>();

    public void splitIntoSpecificLists(final List<AppEntityXmlConfiguration> xmlEntities) {

        if (xmlEntities != null && !xmlEntities.isEmpty()) {
            for (final AppEntityXmlConfiguration appEntity : xmlEntities) {

                final List<XmlEntity> xmlEntityItem = appEntity.getEntitiesInfo();
                if (xmlEntityItem != null && !xmlEntityItem.isEmpty()) {
                    entitiesList.addAll(xmlEntityItem);
                }

                final List<XmlCAEntity> xmlCAEntityItem = appEntity.getCAEntitiesInfo();
                if (xmlCAEntityItem != null && !xmlCAEntityItem.isEmpty()) {
                    cAentitiesList.addAll(xmlCAEntityItem);
                }

            }
        }
    }

    /**
     * @return the entitiesList
     */
    public List<XmlEntity> getEntitiesList() {
        return entitiesList;
    }

    /**
     * @return the cAentitiesList
     */
    public List<XmlCAEntity> getCAentitiesList() {
        return cAentitiesList;
    }

}
