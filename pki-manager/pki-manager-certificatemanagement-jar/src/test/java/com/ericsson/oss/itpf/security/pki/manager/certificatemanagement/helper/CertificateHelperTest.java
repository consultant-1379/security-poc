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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import static org.junit.Assert.assertEquals;

import java.util.*;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateHelperTest {

    @InjectMocks
    CertificateHelper certHelper;

    private static CertificateData certificateData;
    private static SetUPData setUPData;
    private CAEntity caEntity;
    private EntityProfile entityProfile;
    private Algorithm keyGenerationAlgorithm;
    private CertificateProfile certProf;

    @BeforeClass
    public static void setUP() {

        setUPData = new SetUPData();
        certificateData = new CertificateData();
        certificateData.setSerialNumber("10101");

    }

    @Test
    public void testGetMappedCertificateData() {

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(certificateData);
        final CertificateData certDataActual = certHelper.getMappedCertificateData(certificateDatas, certificateData.getSerialNumber());

        assertEquals(certificateData, certDataActual);
        assertEquals(certificateData.getSerialNumber(), certDataActual.getSerialNumber());
    }

    @Test
    public void testGetMappedCertificateDataWithoutSerialNumber() {

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(certificateData);

        final CertificateData certDataActual = certHelper.getMappedCertificateData(certificateDatas, null);
        assertEquals(certificateData, certDataActual);
    }

    @Test
    public void testGetMappedCertificateDataFromEmptySet() {

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        CertificateData certExpected = null;

        final CertificateData certDataActual = certHelper.getMappedCertificateData(certificateDatas, certificateData.getSerialNumber());
        assertEquals(certExpected, certDataActual);
    }

    @Test
    public void testGetKeyGenerationAlgorithmFromCAEntity() {

        Algorithm expectedEntityKeyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");

        keyGenerationAlgorithm = new Algorithm();

        caEntity = new CAEntity();
        caEntity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        expectedEntityKeyGenerationAlgorithm = caEntity.getKeyGenerationAlgorithm();

        assertEquals(expectedEntityKeyGenerationAlgorithm, certHelper.getKeyGenerationAlgorithm(caEntity));
    }

    @Test
    public void testGetKeyGenerationAlgorithmFromEntityProfile() {

        keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");
        entityProfile = new EntityProfile();
        entityProfile.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        caEntity = new CAEntity();
        caEntity.setEntityProfile(entityProfile);

        assertEquals(keyGenerationAlgorithm, certHelper.getKeyGenerationAlgorithm(caEntity));
    }

    @Test
    public void testGetKeyGenerationAlgorithmFromCertificateProfile() {

        keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");
        entityProfile = new EntityProfile();
        certProf = new CertificateProfile();
        caEntity = new CAEntity();
        final List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();

        keygenerationAlgorithms.add(keyGenerationAlgorithm);
        certProf.setKeyGenerationAlgorithms(keygenerationAlgorithms);
        entityProfile.setCertificateProfile(certProf);
        caEntity.setEntityProfile(entityProfile);

        assertEquals(keyGenerationAlgorithm, certHelper.getKeyGenerationAlgorithm(caEntity));
    }

    @Test(expected = InvalidCAException.class)
    public void testGetKeyGenerationAlgorithmInvalidCAException() {

        keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");
        entityProfile = new EntityProfile();
        certProf = new CertificateProfile();
        caEntity = new CAEntity();

        Algorithm keyGenerationAlgorithm2 = setUPData.getKeyGenerationAlgorithm("ECDSA");
        List<Algorithm> keygenerationAlgorithms = new ArrayList<Algorithm>();

        keygenerationAlgorithms.add(keyGenerationAlgorithm);
        keygenerationAlgorithms.add(keyGenerationAlgorithm2);
        certProf.setKeyGenerationAlgorithms(keygenerationAlgorithms);
        entityProfile.setCertificateProfile(certProf);
        caEntity.setEntityProfile(entityProfile);
        certHelper.getKeyGenerationAlgorithm(caEntity);
    }

    @Test
    public void testGetKeyGenerationAlgorithmFromEntity() {

        final Entity entity = new Entity();
        keyGenerationAlgorithm = setUPData.getKeyGenerationAlgorithm("RSA");

        entity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        assertEquals(keyGenerationAlgorithm, certHelper.getKeyGenerationAlgorithm(entity));
    }
}
