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
package com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils;

import junit.framework.Assert;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.ProfileType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;

@RunWith(MockitoJUnitRunner.class)
public class ValidationServiceUtilsTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(ValidationServiceUtils.class);

    @InjectMocks
    ValidationServiceUtils validationServiceUtils;

    final ValidateItem validateItem = new ValidateItem();

    @Before
    public void setUp() {
        validateItem.setItem(new Object());
        validateItem.setOperationType(OperationType.CREATE);
    }

    /**
     * Method to test validation Utils
     */
    @Test
    public void testCertProfileValidateItem() {
        validateItem.setItemType(ItemType.CERTIFICATE_PROFILE);
        Assert.assertEquals(validateItem.getItemType(), validationServiceUtils.generateProfileValidateItem(ProfileType.CERTIFICATE_PROFILE, OperationType.CREATE, new Object()).getItemType());

    }

    /**
     * Method to test validation Utils
     */
    @Test
    public void testEntityProfileValidateItem() {
        validateItem.setItemType(ItemType.ENTITY_PROFILE);
        Assert.assertSame(validateItem.getItemType(), validationServiceUtils.generateProfileValidateItem(ProfileType.ENTITY_PROFILE, OperationType.CREATE, new Object()).getItemType());

    }

    /**
     * Method to test validation Utils
     */
    @Test
    public void testTrustProfileValidateItem() {
        validateItem.setItemType(ItemType.TRUST_PROFILE);
        Assert.assertSame(validateItem.getItemType(), validationServiceUtils.generateProfileValidateItem(ProfileType.TRUST_PROFILE, OperationType.CREATE, new Object()).getItemType());

    }

    /**
     * Method to test validation Utils
     */
    @Test
    public void testEntityValidateItem() {
        validateItem.setItemType(ItemType.ENTITY);
        Assert.assertSame(validateItem.getItemType(), validationServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, new Object()).getItemType());

    }

    /**
     * Method to test validation Utils
     */
    @Test
    public void testCaEntityValidateItem() {
        validateItem.setItemType(ItemType.CA_ENTITY);
        Assert.assertSame(validateItem.getItemType(), validationServiceUtils.generateEntityValidateItem(EntityType.CA_ENTITY, OperationType.CREATE, new Object()).getItemType());

    }

    /**
     * Method to test validation Utils
     */
    @Test
    public void testCertificateValidateItem() {
        validateItem.setItemType(ItemType.X509CERTIFICATE);
        Assert.assertSame(validateItem.getItemType(), validationServiceUtils.generateX509CertificateValidateItem(ItemType.X509CERTIFICATE, OperationType.VALIDATE, new Object(), false).getItemType());

    }
}
