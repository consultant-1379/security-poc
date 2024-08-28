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

@RunWith(MockitoJUnitRunner.class)
public class ExternalCRLInfoDataTest {

    ExternalCRLInfoData externalCRLInfoData;
    ExternalCRLInfoData expectedExternalCRLInfoData;

    @Before
    public void setUp() {

        externalCRLInfoData = getExternalCRLInfoData();
        expectedExternalCRLInfoData = getExternalCRLInfoData();

    }

    @Test
    public void testExternalCRLInfoData() {

        externalCRLInfoData.onCreate();
        externalCRLInfoData.onUpdate();
        externalCRLInfoData.getAutoUpdateCheckTimer();
        externalCRLInfoData.getCreatedDate();
        externalCRLInfoData.getCrl();
        externalCRLInfoData.getId();
        externalCRLInfoData.getModifiedDate();
        externalCRLInfoData.getNextUpdate();
        externalCRLInfoData.getUpdateUrl();
        externalCRLInfoData.hashCode();
        externalCRLInfoData.toString();
        externalCRLInfoData.toSktring();
        externalCRLInfoData.getSerialversionuid();

        assertTrue(externalCRLInfoData.equals(externalCRLInfoData));

        externalCRLInfoData.equals(null);
        externalCRLInfoData.equals(expectedExternalCRLInfoData);

        assertFalse(externalCRLInfoData.equals(new String("test")));

    }

    private ExternalCRLInfoData getExternalCRLInfoData() {
        ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setAutoUpdate(true);
        externalCrlInfoData.setAutoUpdateCheckTimer(0);
        externalCrlInfoData.setNextUpdate(new Date());
        externalCrlInfoData.setUpdateUrl("url");
        return externalCrlInfoData;
    }

}
