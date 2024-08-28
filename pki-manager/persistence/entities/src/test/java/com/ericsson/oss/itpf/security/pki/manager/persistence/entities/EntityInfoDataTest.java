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
package com.ericsson.oss.itpf.security.pki.manager.persistence.entities;

import static org.junit.Assert.*;

import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;

@RunWith(MockitoJUnitRunner.class)
public class EntityInfoDataTest {

    EntityDataSetUp setUpData;
    EntityData entityData;
    EntityInfoData entityInfoData;
    EntityData expectedEntityData;
    EntityInfoData expectedEntityInfoData;

    @Before
    public void setup() {
        setUpData = new EntityDataSetUp();
        entityData = setUpData.createEntityData();
        expectedEntityData = setUpData.createEntityData();

        entityInfoData = entityData.getEntityInfoData();
        expectedEntityInfoData = expectedEntityData.getEntityInfoData();

        entityInfoData.getCertificateDatas();
        entityInfoData.getCreatedDate();
        entityInfoData.getIssuer();
        entityInfoData.getModifiedDate();
        entityInfoData.getName();
        entityInfoData.getOtp();
        entityInfoData.hashCode();
        entityInfoData.getOtpCount();
        entityInfoData.getStatus();
        entityInfoData.getSubjectAltName();
        entityInfoData.getSubjectDN();
        entityInfoData.setCreatedDate(new Date());
        entityInfoData.setModifiedDate(new Date());
    }

    @Test
    public void testEntityInfoSetUp() {
        assertNotNull(entityInfoData.toString());
    }

    @Test
    public void testEntityInfoEquals() {
        entityInfoData.equals(entityInfoData);
        entityInfoData.equals(expectedEntityInfoData);
        entityInfoData.equals(null);
        assertFalse(entityInfoData.equals(new EntityDataTest()));

    }

    @Test
    public void testEntityInfoNotEqualsNoIssuer() {

        CAEntityData issuer = entityInfoData.getIssuer();
        issuer.setId(3);
        entityInfoData.setIssuer(issuer);
        entityInfoData.equals(expectedEntityInfoData);
        entityInfoData.setIssuer(null);

        assertFalse(entityInfoData.equals(expectedEntityInfoData));

    }

    @Test
    public void testEntityInfoNotEquals() {

        entityInfoData.setIssuer(expectedEntityInfoData.getIssuer());

        String name = entityInfoData.getName();

        entityInfoData.setName("Tests");

        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setName(null);

        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setName(name);

        String otp = entityInfoData.getOtp();
        entityInfoData.setOtp("100");
        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setOtp(null);
        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setOtp(otp);

        int otpcount = entityInfoData.getOtpCount();
        entityInfoData.setOtpCount(10);

        assertFalse(entityInfoData.equals(expectedEntityInfoData));

        entityInfoData.setOtpCount(otpcount);

        entityInfoData.setStatus(EntityStatus.INACTIVE);

        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setStatus(null);

        assertFalse(entityInfoData.equals(expectedEntityInfoData));

        entityInfoData.setStatus(expectedEntityInfoData.getStatus());

        entityInfoData.setSubjectAltName("Test");
        entityInfoData.equals(entityInfoData);

        entityInfoData.setSubjectAltName(null);
        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setSubjectAltName(expectedEntityInfoData.getSubjectAltName());

        entityInfoData.setSubjectDN("Tsssest");
        entityInfoData.equals(expectedEntityInfoData);

        entityInfoData.setSubjectDN(null);

        assertFalse(entityInfoData.equals(expectedEntityInfoData));

    }

}
