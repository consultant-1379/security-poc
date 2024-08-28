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
package com.ericsson.oss.itpf.security.pki.manager.test.setup;

import java.text.ParseException;
import java.util.HashSet;
import java.util.Set;

import javax.xml.datatype.DatatypeConfigurationException;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

public class EntitySetUpData {

    private Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetails>();

    /**
     * Method that returns valid Entity
     * 
     * @return Entity
     * @throws ParseException
     * @throws DatatypeConfigurationException
     */
    public Entity getEntityForEqual() throws ParseException, DatatypeConfigurationException {
        final Entity entity = new Entity();
        entity.setEntityInfo((EntityInfo) new EntityInfoSetUpData().build());
        entity.setEntityProfile(new EntityProfileSetUpData().getEntityProfileForEqual());
        entity.setPublishCertificatetoTDPS(true);
        entity.setType(EntityType.ENTITY);
        final Algorithm keyGenerationAlgorithm = new KeyGenerationAlgorithmSetUpData().getAlgorithmForEqual();
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        entity.setCategory(new EntityCategorySetUpData().getEntityCategory());
        entity.setSubjectUniqueIdentifierValue("nmsadm");
        entity.setCertificateExpiryNotificationDetails(certificateExpiryNotificationDetails);
        entity.setOtpValidityPeriod(30);
        return entity;
    }

    /**
     * Method that returns different valid Entity
     * 
     * @return Entity
     * @throws ParseException
     * @throws DatatypeConfigurationException
     */
    public Entity getEntityForNotEqual() throws ParseException, DatatypeConfigurationException {
        final Entity entity = new Entity();
        entity.setEntityInfo((EntityInfo) new EntityInfoSetUpData().build());
        entity.setEntityProfile(new EntityProfileSetUpData().getEntityProfileForNotEqual());
        entity.setPublishCertificatetoTDPS(false);
        entity.setType(EntityType.ENTITY);
        final Algorithm keyGenerationAlgorithm = new KeyGenerationAlgorithmSetUpData().getAlgorithmForNotEqual();
        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        entity.setCategory(new EntityCategorySetUpData().getEntityCategory());
        entity.setSubjectUniqueIdentifierValue("nmsadm1");
        entity.setCertificateExpiryNotificationDetails(certificateExpiryNotificationDetails);
        entity.setOtpValidityPeriod(10);
        return entity;
    }

}
