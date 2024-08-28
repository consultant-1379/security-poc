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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.CertificateEventInfo;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.TDPSEventNotificationService;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.model.TDPSAcknowledgementStatus;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

@RunWith(MockitoJUnitRunner.class)
public class CertificateEventInfoTest {

    @InjectMocks
    CertificateEventInfo certificateEventInfo;

    @Test
    public void testHashcode() {
        int hashCode = certificateEventInfo.hashCode();

        Assert.assertNotNull(hashCode);

    }

    @Test
    public void testEquals() {
        boolean condition = certificateEventInfo.equals(certificateEventInfo);
        Assert.assertTrue(condition);
    }

    @Test
    public void testEqualsGetClassDiff() {
        TDPSEventNotificationService trustDistributionServiceEventNotifier = new TDPSEventNotificationService();

        boolean condition = certificateEventInfo.equals(trustDistributionServiceEventNotifier);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsEntityNameNotSame() {
        CertificateEventInfo certificateEventInfo1 = new CertificateEventInfo();
        certificateEventInfo1.setEntityName("Entity1");
        certificateEventInfo1.setEntityName("Entity");
        boolean condition = certificateEventInfo.equals(certificateEventInfo1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsEntityTypeNull() {
        CertificateEventInfo certificateEventInfo1 = new CertificateEventInfo();
        certificateEventInfo1.setEntityType(EntityType.ENTITY);

        boolean condition = certificateEventInfo.equals(certificateEventInfo1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsEntityTypeNotSame() {
        CertificateEventInfo certificateEventInfo1 = new CertificateEventInfo();
        certificateEventInfo1.setEntityType(EntityType.ENTITY);
        certificateEventInfo.setEntityType(EntityType.CA_ENTITY);
        boolean condition = certificateEventInfo.equals(certificateEventInfo1);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEqualsObjNull() {
        boolean condition = certificateEventInfo.equals(null);
        Assert.assertFalse(condition);
    }

    @Test
    public void testEntityName() {
        CertificateEventInfo certificateEvent = new CertificateEventInfo();
        certificateEvent.setEntityName("entityName");
        boolean condition = certificateEventInfo.equals(certificateEvent);
        Assert.assertFalse(condition);
    }
    @Test
    public void testEntityNameNotSame() {
        CertificateEventInfo certificateEventInfo1 = new CertificateEventInfo();
        certificateEventInfo1.setEntityName("Entity1");
        certificateEventInfo.setEntityName("Entity");
        boolean condition = certificateEventInfo.equals(certificateEventInfo1);
        Assert.assertFalse(condition);
    }
    
    @Test
    public void testEntityNameSame() {
        CertificateEventInfo certificateEventInfo1 = new CertificateEventInfo();
        certificateEventInfo1.setEntityName("Entity");
        certificateEventInfo.setEntityName("Entity");
        boolean condition = certificateEventInfo.equals(certificateEventInfo1);
        Assert.assertTrue(condition);
    }
    
    
    @Test
    public void testTDPSAcknowledgementStatus() {
        TDPSAcknowledgementStatus tdpsAcknowledgementStatus = TDPSAcknowledgementStatus.SUCCESS;
        Assert.assertEquals("Success", tdpsAcknowledgementStatus.getValue());
        String toString = tdpsAcknowledgementStatus.toString();

        Assert.assertEquals("SUCCESS", toString);

    }

}
