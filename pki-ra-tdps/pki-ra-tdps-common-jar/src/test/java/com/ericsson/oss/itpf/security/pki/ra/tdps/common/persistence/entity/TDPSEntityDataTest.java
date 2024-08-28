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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSEntity;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.entity.TDPSEntityData;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSAcknowledgementEvent;

@RunWith(MockitoJUnitRunner.class)
public class TDPSEntityDataTest {

    @InjectMocks
    TDPSEntityData tdpsEntityData;

    @Mock
    TDPSAcknowledgementEvent tDPSAcknowledgementEvent;

    @Test
    public void testHashcode() {
        int hashCode = tdpsEntityData.hashCode();

        Assert.assertNotNull(hashCode);

    }

    @Test
    public void testToString() {

        final String testString = tdpsEntityData.toString();
        Assert.assertNotNull(testString);
    }

    @Test
    public void testEquals() {
        boolean condition = tdpsEntityData.equals(tdpsEntityData);
        Assert.assertTrue(condition);
    }

    @Test
    public void testEqualsGetClassOtherSerialNoDiff() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setSerialNo("1");
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherSerialNoSame() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setSerialNo("1");
        tdpsEntityData.setSerialNo("2");
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherEntityNameDiff() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setEntityName("ENTITY");
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherEntityNameSame() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setEntityName("ENTITY");
        tdpsEntityData.setEntityName("name");
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassSame() {

        boolean condition = tdpsEntityData.equals(tDPSAcknowledgementEvent);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherEntityTypeDiff() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setEntityType(TDPSEntity.ENTITY);
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherEntityTypeSame() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setEntityType(TDPSEntity.ENTITY);
        tdpsEntityData.setEntityType(TDPSEntity.CA_ENTITY);
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherIssuerNameDiff() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setIssuerName("IssuerName");
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsGetClassOtherIssuerNameSame() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();
        tdpsEntityData1.setIssuerName("IssuerName");
        tdpsEntityData.setIssuerName("Issuer");
        boolean condition = tdpsEntityData.equals(tdpsEntityData1);

        Assert.assertFalse(condition);

    }

    @Test
    public void testEqualsCertificateNotSame() {
        TDPSEntityData tdpsEntityData1 = new TDPSEntityData();

        tdpsEntityData1.setCertificate(new byte[] { 1 });
        tdpsEntityData.setCertificate(new byte[] { 2 });

        boolean condition = tdpsEntityData.equals(tdpsEntityData1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsforNull() {
        boolean condition = tdpsEntityData.equals(null);

        Assert.assertFalse(condition);
    }
}
