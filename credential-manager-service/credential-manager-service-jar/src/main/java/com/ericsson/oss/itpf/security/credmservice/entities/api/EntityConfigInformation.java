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
package com.ericsson.oss.itpf.security.credmservice.entities.api;

import java.util.List;

import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEntity;

public interface EntityConfigInformation {

    List<XmlEntity> getEntitiesInfo();

    List<XmlCAEntity> getCAEntitiesInfo();

    String getXmlFilePath();

}
