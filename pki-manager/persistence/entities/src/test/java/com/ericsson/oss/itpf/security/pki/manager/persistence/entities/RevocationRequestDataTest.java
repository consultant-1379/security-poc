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

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.CrlEntryExtensions;
import com.ericsson.oss.itpf.security.pki.common.model.crl.entryextension.InvalidityDate;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationRequestStatus;

@RunWith(MockitoJUnitRunner.class)
public class RevocationRequestDataTest {

    RevocationRequestData revocationRequestData;
    RevocationRequestData expectedRevocationRequestData;

    Date currentTime = new Date();

    @Before
    public void setUp() {
        revocationRequestData = getRevocationRequestData();
        expectedRevocationRequestData = getRevocationRequestData();
    }

    @Test
    public void testRevocationRequestDataForEquals() {

        revocationRequestData.getEntity();
        revocationRequestData.hashCode();
        revocationRequestData.toString();
        revocationRequestData.getCaEntity();
        revocationRequestData.getCertificatesToRevoke();
        revocationRequestData.getCrlEntryExtensionsJSONData();
        revocationRequestData.getId();
        revocationRequestData.getStatus();
        revocationRequestData.setId(10);

        assertTrue(revocationRequestData.equals(revocationRequestData));

        revocationRequestData.equals(null);
        revocationRequestData.equals(expectedRevocationRequestData);

        assertFalse(revocationRequestData.equals(new CrlEntryExtensions()));
    }

    @Test
    public void testRevocationRequestDataNotEquals() {
        revocationRequestData = getRevocationRequestData();
        expectedRevocationRequestData = getRevocationRequestData();
        CAEntityData caData = revocationRequestData.getCaEntity();
        caData.setId(100);
        revocationRequestData.setCaEntity(caData);
        revocationRequestData.equals(expectedRevocationRequestData);
        revocationRequestData.setCaEntity(null);
        revocationRequestData.equals(expectedRevocationRequestData);
        revocationRequestData.setCaEntity(expectedRevocationRequestData.getCaEntity());

        EntityData entityData = revocationRequestData.getEntity();

        entityData.setId(101010);

        assertTrue(revocationRequestData.equals(expectedRevocationRequestData));

        revocationRequestData.setEntity(expectedRevocationRequestData.getEntity());

        revocationRequestData.setId(100);

        revocationRequestData.equals(expectedRevocationRequestData);

        revocationRequestData.setId(10);

        revocationRequestData.setStatus(RevocationRequestStatus.REVOKED);

        assertFalse(revocationRequestData.equals(expectedRevocationRequestData));

    }

    private RevocationRequestData getRevocationRequestData() {
        RevocationRequestData revocationRequestData = new RevocationRequestData();
        CrlEntryExtensions crlEntryExtensions = new CrlEntryExtensions();
        revocationRequestData.setId(10);
        revocationRequestData.setStatus(RevocationRequestStatus.NEW);
        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setId(345678);
        InvalidityDate invalidityDateObject = new InvalidityDate();
        invalidityDateObject.setInvalidityDate(currentTime);
        crlEntryExtensions.setInvalidityDate(invalidityDateObject);
        EntityData entityData = prepareEntityData();
        revocationRequestData.setCrlEntryExtensionsJSONData(JsonUtil.getJsonFromObject(crlEntryExtensions));
        revocationRequestData.setEntity(entityData);
        revocationRequestData.setCaEntity(caEntityData);
        return revocationRequestData;
    }

    private EntityData prepareEntityData() {
        EntityData entityData = new EntityData();
        entityData.setId(101010);
        entityData.setPublishCertificatetoTDPS(true);
        return entityData;
    }
}
