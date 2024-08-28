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
package com.ericsson.oss.itpf.security.credmsapi;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.CommandPhase;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ConfigurationException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.EntityNotFoundException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.GetCertificatesByEntityNameException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpExpiredException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.OtpNotValidException;
import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.RevokeCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.TrustSource;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PropertiesReader;
import com.ericsson.oss.itpf.security.credmservice.api.CredMService;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerAlreadyRevokedCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateGenerationException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerCertificateNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerEntityNotFoundException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerExpiredCertificateException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInternalServiceException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidArgumentException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerInvalidOtpException;
import com.ericsson.oss.itpf.security.credmservice.api.exception.CredentialManagerOtpExpiredException;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerAlgorithm;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCRLIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateIdentifier;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCrlMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityStatus;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntityType;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPKCS10CertRequest;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubject;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX500CertificateSummary;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;

@RunWith(MockitoJUnitRunner.class)
public class CredMServiceWrapperTest {

    @InjectMocks
    CredMServiceWrapper mockWrapper;

    @Mock
    static CredMService mockRmiClient;

    @Mock
    static CredentialManagerServiceRestClient mockRestClient;

    @Test
    public void testCredMServiceWrapper() {

        CredMServiceWrapper wrapper = null;
        try {
            wrapper = new CredMServiceWrapper(CredMServiceWrapper.channelMode.SECURE_CHANNEL, true);
        } catch (final IssueCertificateException e1) {
            assertTrue("CredMServiceWrapperTest", true);
        }

        // change properties to point to unexixting host
        try {
            final Properties props = PropertiesReader.getProperties(PropertiesReader.getConfigFile());
            props.setProperty(PropertiesReader.ADDRESS, "ip1:1,ip2:2");
        } catch (final ConfigurationException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        // REST
        try {
            wrapper = new CredMServiceWrapper(CredMServiceWrapper.channelMode.REST_CHANNEL_TEST, true);
        } catch (final IssueCertificateException e) {
            assertTrue("CredMServiceWrapperTest: sps host not found", true);
        }
        assertTrue("CredMServiceWrapperTest", wrapper == null);

        final CredMServiceWrapper wrapp2 = new CredMServiceWrapper(null, null);
        assertNull(wrapp2.credMService);
        assertNull(wrapp2.restClient);

        CredMServiceWrapperFactory factory = new CredMServiceWrapperFactory();
        CredMServiceWrapper wrap1 = null;
        try {
            wrap1 = factory.buildServiceWrapper(CredMServiceWrapper.channelMode.REST_CHANNEL, true);
            assertTrue(false);
        } catch (IssueCertificateException e) {
            assertTrue(true);
        }
    }

    @Test
    public void getModeTest() {
        final CredMServiceWrapper wrapper = new CredMServiceWrapper();
        assertEquals(wrapper.getMode(), CredMServiceWrapper.channelMode.SECURE_CHANNEL); //mode is a public field, so the getMode() method is useless
    }

    @Test
    public void testCreateAndGetEndEntity() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerEntity entity = null;
        try {
            entity = wrapper.createAndGetEndEntity("test", "test");
        } catch (final Exception e) {
            assertTrue("testCreateAndGetEndEntity SECURE_CHANNEL", true);
        }

        // fake REST_CHANNEL
        //        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        //        try {
        //            entity = wrapper.createAndGetEndEntity("test", "test");
        //        } catch (final Exception e) {
        //            assertTrue("testCreateAndGetEndEntity REST_CHANNEL", false);
        //        }
        //        assertTrue("testCreateAndGetEndEntity REST_CHANNEL", entity == null);
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            entity = wrapper.createAndGetEndEntity("test", "test");
        } catch (final Exception e) {
            assertTrue("testCreateAndGetEndEntity REST_CHANNEL_TEST", true);
        }

        // REST
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        CredentialManagerEntity ent1 = null;
        final CredentialManagerEntity ent2 = new CredentialManagerEntity();
        when(mockRestClient.createAndGetEndEntity(Matchers.anyString(), Matchers.anyString())).thenReturn(ent2);

        try {
            ent1 = this.mockWrapper.createAndGetEndEntity("test", "test");
        } catch (final IssueCertificateException e) {
            e.printStackTrace(); //it does not pass here
        }

        assertEquals(ent1.getEntityStatus(), CredentialManagerEntityStatus.NEW);

    }

    @Test
    public void testCreateAndGetEntity() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerEntity entity = null;
        try {
            entity = wrapper.createAndGetEntity("test", null, null, null, "test");
        } catch (final Exception e) {
            assertTrue("testCreateAndGetEntity SECURE_CHANNEL", false);
        }
        assertTrue("testCreateAndGetEntity SECURE_CHANNEL", entity == null);

        // fake REST 
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            entity = wrapper.createAndGetEntity("test", null, null, null, "test");
            assertTrue("testCreateAndGetEntity REST_CHANNEL_TEST", false);
        } catch (final Exception e) {
            assertTrue("testCreateAndGetEntity REST_CHANNEL_TEST", true);
        }

        // REST (createAndGetEntity is not possible via REST)
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            entity = wrapper.createAndGetEntity("test", null, null, null, "test");
            assertTrue("testCreateAndGetEntity REST_CHANNEL", false);
        } catch (final Exception e) {
            assertTrue("testCreateAndGetEntity REST_CHANNEL", true);
        }

        // RMI
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        CredentialManagerEntity ent1 = null;
        when(
                mockRmiClient.createAndGetEntity(Matchers.anyString(), Matchers.any(CredentialManagerSubject.class), Matchers.any(CredentialManagerSubjectAltName.class),
                        Matchers.any(CredentialManagerAlgorithm.class), Matchers.anyString())).thenThrow(new CredentialManagerInternalServiceException());
        try {
            ent1 = this.mockWrapper.createAndGetEntity("test", null, null, null, "test");
        } catch (final IssueCertificateException e) {
            e.printStackTrace(); //it does not pass here
        }
        assertNull(ent1);
    }

    @Test
    public void testGetEntity() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerEntity entity = null;
        try {
            entity = wrapper.getEntity("test");
        } catch (final Exception e) {
            assertTrue("testGetEntity failed", false);
        }
        assertTrue("testGetEntity", entity == null);

        when(mockRmiClient.getEntity(Matchers.anyString())).thenThrow(new CredentialManagerInternalServiceException());
        entity = this.mockWrapper.getEntity("pippo");
        assertNull(entity);
    }

    @Test
    public void testGetExistingEntity() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerEntity entity = null;
        try {
            entity = wrapper.getExistingEntity("entityName");
        } catch (final Exception e) {
            assertTrue("testGetEntity failed", false);
        }
        assertTrue("testGetEntity", entity == null);

        when(mockRmiClient.getEntity(Matchers.anyString())).thenThrow(new CredentialManagerInternalServiceException());
        entity = this.mockWrapper.getExistingEntity("pippo");
        assertNull(entity);
    }

    @Test
    public void testGetCertificate() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerX509Certificate[] certs = null;
        try {
            certs = wrapper.getCertificate(null);
        } catch (final Exception e) {
            assertTrue("testGetCertificate SECURE_CHANNEL", true);
        }

        // REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        when(mockRestClient.getCertificate(Matchers.any(PKCS10CertificationRequest.class))).thenReturn(null);
        try {
            certs = wrapper.getCertificate(null);
        } catch (final Exception e) {
            assertTrue("testGetCertificate REST_CHANNEL", false);
        }
        assertTrue("testGetCertificate REST_CHANNEL", certs == null);

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            certs = wrapper.getCertificate(null);
            assertTrue("testGetCertificate REST_CHANNEL_TEST", false);
        } catch (final Exception e) {
            assertTrue("testGetCertificate REST_CHANNEL_TEST", true);
        }
    }

    @Test
    public void testGetCertificate2() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        /*
         * certificate without Chain
         */
        CredentialManagerX509Certificate[] certArray = null;
        try {
            certArray = wrapper.getCertificate(null, "", false, null);
        } catch (final Exception e) {
            assertTrue("testGetCertificate2 SECURE_CHANNEL without Chain", false);
        }
        assertTrue("testGetCertificate2 SECURE_CHANNEL without Chain", certArray == null);

        /*
         * certificate with Chain
         */
        certArray = null;
        try {
            certArray = wrapper.getCertificate(null, "", true, null);
        } catch (final Exception e) {
            assertTrue("testGetCertificate2 SECURE_CHANNEL with Chain", false);
        }
        assertTrue("testGetCertificate2 SECURE_CHANNEL with Chain", certArray == null);

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        CredentialManagerX509Certificate[] certs = null;
        try {
            certs = wrapper.getCertificate(null);
        } catch (final Exception e) {
            assertTrue("testGetCertificate2 REST_CHANNEL", true);
        }

        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                new CredentialManagerCertificateGenerationException());
        try {
            certArray = this.mockWrapper.getCertificate(null, "pippo1", false, null);
        } catch (final IssueCertificateException | OtpExpiredException | OtpNotValidException e) {
            e.printStackTrace(); //it does not pass here
        }
        assertNull(certArray);

        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            certArray = this.mockWrapper.getCertificate(null, "pippo", false, null);
        } catch (final IssueCertificateException e) {
            assertTrue(true); //it passes here
        } catch (OtpExpiredException e) {
            assertTrue(false);
        } catch (OtpNotValidException e) {
            assertTrue(false);
        }

        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            certArray = this.mockWrapper.getCertificate(null, "pippo", false, null);
        } catch (final IssueCertificateException e) {
            assertTrue(true); //it passes here
        } catch (OtpExpiredException e) {
            assertTrue(false);
        } catch (OtpNotValidException e) {
            assertTrue(false);
        }
    }

    @Test
    public void testGetCertificate3() throws IssueCertificateException, OtpNotValidException {
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        CredentialManagerX509Certificate[] certArray = null;
        when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                new CredentialManagerOtpExpiredException());
        try {
            certArray = this.mockWrapper.getCertificate(null, "pippo1", false, null);
            assertTrue(false);
        } catch (final OtpExpiredException e) {
            assertTrue(true);
        }
        assertNull(certArray);

    }

    @Test
    public void testGetCertificate4() throws IssueCertificateException, OtpExpiredException {
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        CredentialManagerX509Certificate[] certArray = null;
        when(mockRmiClient.getCertificate(Matchers.any(CredentialManagerPKCS10CertRequest.class), Matchers.anyString(), Matchers.anyBoolean(), Matchers.anyString())).thenThrow(
                new CredentialManagerInvalidOtpException());
        try {
            certArray = this.mockWrapper.getCertificate(null, "pippo1", false, null);
            assertTrue(false);
        } catch (final OtpNotValidException e) {
            assertTrue(true);
        }
        assertNull(certArray);

    }

    //    @Test
    //    public void testGetProfile() {
    //
    //        final CredMServiceWrapper wrapper = new CredMServiceWrapper();
    //
    //        CredentialManagerProfileInfo profile = null;
    //        try {
    //            profile = wrapper.getProfile();
    //        } catch (final Exception e) {
    //            assertTrue("testGetProfile SECURE_CHANNEL", false);
    //        }
    //        assertTrue("testGetProfile SECURE_CHANNEL", profile == null);
    //        // fake REST_CHANNEL
    //        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
    //        try {
    //            profile = wrapper.getProfile();
    //        } catch (final Exception e) {
    //            assertTrue("testGetProfile REST_CHANNEL", false);
    //        }
    //        assertTrue("testGetProfile REST_CHANNEL", profile == null);
    //
    //        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
    //        try {
    //            profile = wrapper.getProfile();
    //        } catch (final Exception e) {
    //            assertTrue("testGetProfile REST_CHANNEL_TEST", false);
    //        }
    //        assertTrue("testGetProfile REST_CHANNEL_TEST", profile == null);
    //    }

    @Test
    public void testGetProfile2() {
        CredentialManagerProfileInfo profile = null;
        final CredentialManagerProfileInfo profile1 = new CredentialManagerProfileInfo();
        profile1.setIssuerName("pippoCA");

        //RMI
        when(mockRmiClient.getProfile(Matchers.anyString())).thenReturn(profile1);
        profile = this.mockWrapper.getProfile("pippo");
        assertEquals(profile, profile1);

        when(mockRmiClient.getProfile(Matchers.anyString())).thenThrow(new CredentialManagerInvalidArgumentException());
        profile = this.mockWrapper.getProfile("pippo");
        assertTrue(true);

        //REST
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        profile = this.mockWrapper.getProfile("pippo");
        assertTrue(true);

    }

    @Test
    public void testGetTrustCertificates() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerTrustMaps trustMaps = null;
        try {
            trustMaps = wrapper.getTrustCertificates();
        } catch (final Exception e) {
            assertTrue("testGetTrustCertificates SECURE_CHANNEL", false);
        }
        assertTrue("testGetTrustCertificates SECURE_CHANNEL", trustMaps.getInternalCATrustMap().isEmpty() && trustMaps.getExternalCATrustMap().isEmpty());

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            trustMaps = wrapper.getTrustCertificates();
        } catch (final Exception e) {
            assertTrue("testGetTrustCertificates REST_CHANNEL_TEST", false);
        }
        assertTrue("testGetTrustCertificates REST_CHANNEL_TEST", trustMaps.getInternalCATrustMap().isEmpty() && trustMaps.getExternalCATrustMap().isEmpty());

        //RMI
        CredentialManagerTrustMaps trustMaps2 = null;
        final CredentialManagerTrustMaps trustMaps3 = new CredentialManagerTrustMaps();

        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;

        when(mockRmiClient.getTrustCertificates("")).thenThrow(new CredentialManagerInternalServiceException());
        this.mockWrapper.getTrustCertificates();

        this.mockWrapper.getTrustCertificates("TP", CredentialManagerProfileType.TRUST_PROFILE);
        this.mockWrapper.getTrustCertificates("CP", CredentialManagerProfileType.CERTIFICATE_PROFILE);

        //RMI
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        when(mockRestClient.getTrust()).thenReturn(trustMaps3);
        trustMaps2 = this.mockWrapper.getTrustCertificates();
        assertEquals(trustMaps2, trustMaps3);

    }

    @Test
    public void testGetCrl() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        CredentialManagerCrlMaps crl = null;

        try {
            crl = wrapper.getCRLs("entity", CredentialManagerProfileType.ENTITY_PROFILE);
        } catch (final Exception e) {
            assertTrue("testGetCrl SECURE_CHANNEL", false);
        }
        assertTrue("testGetCrl SECURE_CHANNEL", crl == null);

        try {
            crl = mockWrapper.getCRLs("entity", CredentialManagerProfileType.ENTITY_PROFILE);
        } catch (final Exception e) {
            assertTrue("testGetCrl SECURE_CHANNEL", false);
        }
        assertTrue("testGetCrl SECURE_CHANNEL", crl == null);

        try {
            crl = mockWrapper.getCRLs("entity", CredentialManagerProfileType.TRUST_PROFILE);
        } catch (final Exception e1) {
            assertTrue("testGetCrl SECURE_CHANNEL_TrustProfile", false);
        }

        try {
            crl = mockWrapper.getCRLs("entity", CredentialManagerProfileType.CERTIFICATE_PROFILE);
        } catch (final Exception e2) {
            assertTrue("testGetCrl SECURE_CHANNEL_CertificateProfile", false);
        }

        // REST_CHANNEL (method not allowed)
        mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            crl = mockWrapper.getCRLs("entity", CredentialManagerProfileType.ENTITY_PROFILE);
            assertTrue("testGetTrustCertificates REST_CHANNEL", false);
        } catch (final Exception e3) {
            assertTrue("testGetTrustCertificates REST_CHANNEL", true);
        }

        // fake REST_CHANNEL
        mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            crl = mockWrapper.getCRLs("entity", CredentialManagerProfileType.ENTITY_PROFILE);
            assertTrue("testGetTrustCertificates REST_CHANNEL_TEST", false);
        } catch (final Exception e4) {
            assertTrue("testGetTrustCertificates REST_CHANNEL_TEST", true);
        }
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCompareCrlsAndRetrieve() {

        CredMServiceWrapper wrapper = new CredMServiceWrapper();
        final SortedSet<CredentialManagerCRLIdentifier> currentCrl = null;
        CredentialManagerCrlMaps crls1;
        final CredentialManagerCrlMaps crls2 = new CredentialManagerCrlMaps();
        CredentialManagerCrlMaps crls3 = null;
        CredentialManagerCrlMaps crls4 = null;

        crls3 = wrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentCrl, TrustSource.BOTH);
        assertNull(crls3);

        //RMI
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        when(mockRmiClient.compareCrlsAndRetrieve(Matchers.anyString(), Matchers.anyBoolean(), Matchers.any(SortedSet.class), Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(crls2);
        crls1 = this.mockWrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentCrl, TrustSource.BOTH);
        assertEquals(crls1, crls2);

        when(mockRmiClient.compareCrlsAndRetrieve(Matchers.anyString(), Matchers.anyBoolean(), Matchers.any(SortedSet.class), Matchers.anyBoolean(), Matchers.anyBoolean())).thenThrow(
                new CredentialManagerInvalidArgumentException());
        this.mockWrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentCrl, TrustSource.EXTERNAL);

        when(mockRmiClient.compareCrlsAndRetrieveTP(Matchers.anyString(), Matchers.anyBoolean(), Matchers.any(SortedSet.class), Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(crls2);
        crls4 = this.mockWrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.TRUST_PROFILE, currentCrl, TrustSource.INTERNAL);
        assertEquals(crls4, crls2);
        crls3 = this.mockWrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.CERTIFICATE_PROFILE, currentCrl, TrustSource.INTERNAL);
        assertNull(crls3);

        // REST (method not allowed)
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        crls3 = this.mockWrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentCrl, TrustSource.INTERNAL);
        assertNull(crls3);

        // fake REST_CHANNEL
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        crls3 = this.mockWrapper.compareCRLsAndRetrieve("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentCrl, TrustSource.INTERNAL);
        assertNull(crls3);

    }

    @SuppressWarnings("unchecked")
    @Test
    public void testCheckTrust() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        final SortedSet<CredentialManagerCertificateIdentifier> currentTrust = null;
        CredentialManagerTrustMaps result = null;
        CredentialManagerTrustMaps maps2 = new CredentialManagerTrustMaps();
        try {
            result = wrapper.checkCurrentTrust("", CredentialManagerProfileType.ENTITY_PROFILE, currentTrust, TrustSource.BOTH);
        } catch (final Exception e) {
            assertTrue("testCheckTrust SECURE_CHANNEL", false);
        }
        assertTrue("testCheckTrust SECURE_CHANNEL", result == null);

        // REST (method not allowed)
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            result = wrapper.checkCurrentTrust("", CredentialManagerProfileType.ENTITY_PROFILE, currentTrust, TrustSource.INTERNAL);
        } catch (final Exception e) {
            assertTrue("testCheckTrust SECURE_CHANNEL", false);
        }
        assertTrue("testCheckTrust SECURE_CHANNEL", result == null);

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            result = wrapper.checkCurrentTrust("", CredentialManagerProfileType.ENTITY_PROFILE, currentTrust, TrustSource.EXTERNAL);
        } catch (final Exception e) {
            assertTrue("testCheckTrust REST_CHANNEL_TEST", false);
        }
        assertTrue("testCheckTrust REST_CHANNEL_TEST", result == null);

        // RMI
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;

        when(mockRmiClient.compareTrustAndRetrieve(Matchers.anyString(), Matchers.any(SortedSet.class), Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(maps2);
        result = this.mockWrapper.checkCurrentTrust("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentTrust, TrustSource.BOTH);
        assertEquals(result, maps2);

        result = null;

        when(mockRmiClient.compareTrustAndRetrieveTP(Matchers.anyString(), Matchers.any(SortedSet.class), Matchers.anyBoolean(), Matchers.anyBoolean())).thenReturn(maps2);
        result = this.mockWrapper.checkCurrentTrust("pippo", CredentialManagerProfileType.TRUST_PROFILE, currentTrust, TrustSource.BOTH);
        assertEquals(result, maps2);

        result = null;

        result = this.mockWrapper.checkCurrentTrust("pippo", CredentialManagerProfileType.CERTIFICATE_PROFILE, currentTrust, TrustSource.BOTH);
        assertNull(result);

        when(mockRmiClient.compareTrustAndRetrieve(Matchers.anyString(), Matchers.any(SortedSet.class), Matchers.anyBoolean(), Matchers.anyBoolean())).thenThrow(
                new CredentialManagerInternalServiceException());
        result = this.mockWrapper.checkCurrentTrust("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentTrust, TrustSource.BOTH);
        assertNull(result);

        mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        when(mockRestClient.getTrust()).thenReturn(maps2);
        result = this.mockWrapper.checkCurrentTrust("pippo", CredentialManagerProfileType.ENTITY_PROFILE, currentTrust, TrustSource.BOTH);
        assertEquals(result, maps2);
    }

    @Test
    public void testRevokeCertificateById() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        final CredentialManagerCertificateIdentifier certificateIdentifer = new CredentialManagerCertificateIdentifier();

        Boolean result = false;
        try {
            result = wrapper.revokeCertificateById(certificateIdentifer);
        } catch (final Exception e) {
            assertTrue("testRevokeCertificateById SECURE_CHANNEL", false);
        }
        assertTrue("testRevokeCertificateById SECURE_CHANNEL", result == null);

        //REST (method not allowed)
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        result = false;
        try {
            result = wrapper.revokeCertificateById(certificateIdentifer);
        } catch (final Exception e) {
            assertTrue("testRevokeCertificateById SECURE_CHANNEL", false);
        }
        assertTrue("testRevokeCertificateById SECURE_CHANNEL", result == null);

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        result = false;
        try {
            result = wrapper.revokeCertificateById(certificateIdentifer);
        } catch (final Exception e) {
            assertTrue("testRevokeCertificateById REST_CHANNEL_TEST", false);
        }
        assertTrue("testRevokeCertificateById REST_CHANNEL_TEST", result == null);

        // RMI 
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;

        Mockito.doThrow(new CredentialManagerInternalServiceException()).when(mockRmiClient)
                .revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        try {
            result = this.mockWrapper.revokeCertificateById(certificateIdentifer, CredentialManagerRevocationReason.UNSPECIFIED, null);
        } catch (final CredentialManagerInternalServiceException e) {
            assertNull(result);
        }

        Mockito.doThrow(new CredentialManagerCertificateNotFoundException()).when(mockRmiClient)
                .revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        try {
            result = this.mockWrapper.revokeCertificateById(certificateIdentifer, CredentialManagerRevocationReason.UNSPECIFIED, null);
        } catch (final CredentialManagerCertificateNotFoundException e) {
            assertNull(result);
        }

        Mockito.doThrow(new CredentialManagerAlreadyRevokedCertificateException()).when(mockRmiClient)
                .revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        try {
            result = this.mockWrapper.revokeCertificateById(certificateIdentifer, CredentialManagerRevocationReason.UNSPECIFIED, null);
        } catch (final CredentialManagerAlreadyRevokedCertificateException e) {
            assertNull(result);
        }

        Mockito.doThrow(new CredentialManagerExpiredCertificateException()).when(mockRmiClient)
                .revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        try {
            result = this.mockWrapper.revokeCertificateById(certificateIdentifer, CredentialManagerRevocationReason.UNSPECIFIED, null);
        } catch (final CredentialManagerExpiredCertificateException e) {
            assertNull(result);
        }

    }

    @Test
    public void testRevokeCertificateById_2() {

        final CredentialManagerCertificateIdentifier certificateIdentifer = new CredentialManagerCertificateIdentifier();
        Boolean result = false;

        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerAlreadyRevokedCertificateException());
        result = this.mockWrapper.revokeCertificateById(certificateIdentifer);
        assertTrue(result == false);

    }

    @Test
    public void testRevokeCertificateById_3() {
        final CredentialManagerCertificateIdentifier certificateIdentifer = new CredentialManagerCertificateIdentifier();
        Boolean result = false;

        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerExpiredCertificateException());
        result = this.mockWrapper.revokeCertificateById(certificateIdentifer);
        assertTrue(result == false);
    }

    @Test
    public void testRevokeCertificateById_4() {
        final CredentialManagerCertificateIdentifier certificateIdentifer = new CredentialManagerCertificateIdentifier();
        Boolean result = false;

        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerCertificateNotFoundException());
        result = this.mockWrapper.revokeCertificateById(certificateIdentifer);
        assertTrue(result == true);
    }

    @Test
    public void testRevokeCertificateById_5() {
        final CredentialManagerCertificateIdentifier certificateIdentifer = new CredentialManagerCertificateIdentifier();
        Boolean result = false;

        when(this.mockWrapper.revokeCertificateById(Matchers.any(CredentialManagerCertificateIdentifier.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class)))
                .thenThrow(new CredentialManagerInternalServiceException());
        result = this.mockWrapper.revokeCertificateById(certificateIdentifer);
        assertTrue(result == false);
    }

    @Test
    public void testListActiveCertificates() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();
        List<CredentialManagerX509Certificate> retList = new ArrayList<CredentialManagerX509Certificate>();

        List<CredentialManagerX509Certificate> result = null;
        try {
            result = wrapper.listActiveCertificates("entity");
        } catch (final Exception e) {
            assertTrue("testListActiveCertificates SECURE_CHANNEL", false);
        }
        assertTrue("testListActiveCertificates SECURE_CHANNEL", result == null);

        // RMI (method not allowed)
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            result = wrapper.listActiveCertificates("entity");
        } catch (final Exception e) {
            assertTrue("testListActiveCertificates SECURE_CHANNEL", false);
        }
        assertTrue("testListActiveCertificates SECURE_CHANNEL", result == null);

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            result = wrapper.listActiveCertificates("entity");
        } catch (final Exception e) {
            assertTrue("testListActiveCertificates REST_CHANNEL_TEST", false);
        }
        assertTrue("testListActiveCertificates REST_CHANNEL_TEST", result == null);

        // RMI
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;

        when(mockRmiClient.listCertificates("pippo", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE)).thenReturn(retList);
        result = this.mockWrapper.listActiveCertificates("pippo");
        assertEquals(result, retList);

        result = null;
        when(mockRmiClient.listCertificates(Matchers.anyString(), Matchers.any(CredentialManagerEntityType.class), Matchers.any(CredentialManagerCertificateStatus.class))).thenThrow(
                new CredentialManagerInternalServiceException());
        result = this.mockWrapper.listActiveCertificates("pippo");
        assertNull(result);
    }

    @Test
    public void testGetEntitiesByCategory() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        Set<CredentialManagerEntity> result = null;
        try {
            result = wrapper.getEntitiesByCategory("category");
        } catch (final Exception e) {
            assertTrue("testGetEntitiesByCategory SECURE_CHANNEL", false);
        }
        assertTrue("testGetEntitiesByCategory SECURE_CHANNEL", result == null);

        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        when(mockRmiClient.getEntitiesByCategory(Matchers.anyString())).thenReturn(null);
        result = this.mockWrapper.getEntitiesByCategory("pippo");
        assertNull(result);

    }

    @Test
    public void testIsOTPValid() {
        final CredMServiceWrapper wrapper = new CredMServiceWrapper();
        boolean result = false;
        wrapper.isOTPValid("pippo", "otp1");
        when(mockRmiClient.isOTPValid("pippo", "otp2")).thenReturn(true);
        result = mockWrapper.isOTPValid("pippo", "otp2");
        assertTrue(result);

    }

    @Test
    public void testRevokeCertificateByEntity() throws RevokeCertificateException, EntityNotFoundException {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        try {
            wrapper.revokeCertificateByEntity("entityName", CredentialManagerRevocationReason.KEY_COMPROMISE, new Date());
            assertTrue("testRevokeCertificateByEntity: success", true);
        } catch (final RevokeCertificateException e) {
            assertTrue("testRevokeCertificateByEntity: unexpected revokeCertificate exception", false);
        } catch (final EntityNotFoundException e) {
            assertTrue("testRevokeCertificateByEntity: unexpected entityNotFound exception", false);
        }

        // REST (method not allowed)
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            wrapper.revokeCertificateByEntity("entityName", CredentialManagerRevocationReason.KEY_COMPROMISE, new Date());
            assertTrue("testRevokeCertificateByEntity: exception not occurred", false);
        } catch (final RevokeCertificateException e) {
            assertTrue("testRevokeCertificateByEntity: exception expected", true);
        } catch (final EntityNotFoundException e) {
            assertTrue("testRevokeCertificateByEntity: exception expected", true);
        }

        // fake REST_CHANNEL
        wrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            wrapper.revokeCertificateByEntity("entityName", CredentialManagerRevocationReason.KEY_COMPROMISE, new Date());
            assertTrue("testRevokeCertificateByEntity: exception not occurred", false);
        } catch (final RevokeCertificateException e) {
            assertTrue("testRevokeCertificateByEntity: exception expected", true);
        } catch (final EntityNotFoundException e) {
            assertTrue("testRevokeCertificateByEntity: exception expected", true);
        }

        // RMI
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;

        this.mockWrapper.revokeCertificateByEntity("pippo", CredentialManagerRevocationReason.UNSPECIFIED, null);

        Mockito.doThrow(new CredentialManagerInternalServiceException()).when(mockRmiClient)
                .revokeCertificateByEntity(Matchers.any(String.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        try {
            this.mockWrapper.revokeCertificateByEntity("pippo", CredentialManagerRevocationReason.UNSPECIFIED, null);
        } catch (final RevokeCertificateException e) {
            assertTrue(true);
        }

        Mockito.doThrow(new CredentialManagerEntityNotFoundException()).when(mockRmiClient)
                .revokeCertificateByEntity(Matchers.any(String.class), Matchers.any(CredentialManagerRevocationReason.class), Matchers.any(Date.class));
        try {
            this.mockWrapper.revokeCertificateByEntity("pippo", CredentialManagerRevocationReason.UNSPECIFIED, null);
        } catch (final EntityNotFoundException e) {
            assertTrue(true);
        }

    }

    @Test
    public void printCommandonSystemRecTest() {
        CredMServiceWrapper wrapper = new CredMServiceWrapper();

        wrapper.printCommandOnSystemRecorder(null, CommandPhase.ONGOING, "test", "pippo", null);

        this.mockWrapper.printCommandOnSystemRecorder(null, CommandPhase.ONGOING, "test", "pippo", null);

        Mockito.doThrow(new IllegalArgumentException()).when(mockRmiClient)
                .printCommandOnRecorder(Matchers.any(String.class), Matchers.any(CommandPhase.class), Matchers.any(String.class), Matchers.any(String.class), Matchers.any(String.class));
        this.mockWrapper.printCommandOnSystemRecorder(null, CommandPhase.ONGOING, "test", "pippo", null);
        assertTrue(true);
    }

    @Test
    public void printErroronSystemRecTest() {
        CredMServiceWrapper wrapper = new CredMServiceWrapper();

        wrapper.printErrorOnSystemRecorder("message", ErrorSeverity.DEBUG, "test", "pippo", null);

        this.mockWrapper.printErrorOnSystemRecorder(null, ErrorSeverity.DEBUG, "test", "pippo", null);

        Mockito.doThrow(new IllegalArgumentException()).when(mockRmiClient)
                .printErrorOnRecorder(Matchers.any(String.class), Matchers.any(ErrorSeverity.class), Matchers.any(String.class), Matchers.any(String.class), Matchers.any(String.class));
        this.mockWrapper.printErrorOnSystemRecorder(null, ErrorSeverity.DEBUG, "test", "pippo", null);
        assertTrue(true);
    }

    @Test
    public void getPibParamsTest() {
        CredMServiceWrapper wrapper = new CredMServiceWrapper();
        CredentialManagerPIBParameters result = null;
        CredentialManagerPIBParameters checkPIB = new CredentialManagerPIBParameters();
        checkPIB.setServiceCertAutoRenewalTimer(1);
        result = wrapper.getPibParameters();
        assertNotNull(result);

        when(mockRmiClient.getPibParameters()).thenReturn(checkPIB);
        result = mockWrapper.getPibParameters();
        assertEquals(result, checkPIB);
    }

    @Test
    public void testGetCertificatesByEntityName() {

        final CredMServiceWrapper wrapper = new CredMServiceWrapper();

        //// first test
        List<CredentialManagerX500CertificateSummary> result = null;
        try {
            result = wrapper.getCertificatesByEntityName("entity", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
        } catch (final Exception e) {
            assertTrue("Exceptions not expected", false);
        }
        assertTrue("testGetCertificatesByEntityName; first test : result not null", result == null);

        //// second test
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        when(mockRmiClient.listCertificatesSummary(Matchers.anyString(), Matchers.eq(CredentialManagerEntityType.ENTITY), Matchers.eq(CredentialManagerCertificateStatus.ACTIVE))).thenReturn(null);
        try {
            result = this.mockWrapper.getCertificatesByEntityName("pippo", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
        } catch (CertificateNotFoundException | GetCertificatesByEntityNameException | EntityNotFoundException e) {
            assertTrue("Exceptions not expected", false);
        }
        assertNull("testGetCertificatesByEntityName; second test : result not null", result);

    }

    @Test
    public void testGetCertificatesByEntityNameExceptions() throws CertificateNotFoundException, GetCertificatesByEntityNameException, EntityNotFoundException {
        List<CredentialManagerX500CertificateSummary> result = null;
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.SECURE_CHANNEL;
        when(
                mockRmiClient.listCertificatesSummary(Matchers.eq("CredentialManagerCertificateNotFoundException"), Matchers.eq(CredentialManagerEntityType.ENTITY),
                        Matchers.eq(CredentialManagerCertificateStatus.ACTIVE))).thenThrow(new CredentialManagerCertificateNotFoundException());
        try {
            result = this.mockWrapper.getCertificatesByEntityName("CredentialManagerCertificateNotFoundException", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (CertificateNotFoundException e) {
            assertTrue(result == null);
        }
        when(
                mockRmiClient.listCertificatesSummary(Matchers.eq("CredentialManagerEntityNotFoundException"), Matchers.eq(CredentialManagerEntityType.ENTITY),
                        Matchers.eq(CredentialManagerCertificateStatus.ACTIVE))).thenThrow(new CredentialManagerEntityNotFoundException());
        try {
            result = this.mockWrapper.getCertificatesByEntityName("CredentialManagerEntityNotFoundException", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (EntityNotFoundException e) {
            assertTrue(result == null);
        }
        when(
                mockRmiClient.listCertificatesSummary(Matchers.eq("CredentialManagerInternalServiceException"), Matchers.eq(CredentialManagerEntityType.ENTITY),
                        Matchers.eq(CredentialManagerCertificateStatus.ACTIVE))).thenThrow(new CredentialManagerInternalServiceException());
        try {
            result = this.mockWrapper.getCertificatesByEntityName("CredentialManagerInternalServiceException", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (GetCertificatesByEntityNameException e) {
            assertTrue(result == null);
        }
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL;
        try {
            result = this.mockWrapper.getCertificatesByEntityName("CredentialManagerInternalServiceException", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (GetCertificatesByEntityNameException e) {
            assertTrue(result == null);
        }
        this.mockWrapper.mode = CredMServiceWrapper.channelMode.REST_CHANNEL_TEST;
        try {
            result = this.mockWrapper.getCertificatesByEntityName("CredentialManagerInternalServiceException", CredentialManagerEntityType.ENTITY, CredentialManagerCertificateStatus.ACTIVE);
            assertTrue(false);
        } catch (GetCertificatesByEntityNameException e) {
            assertTrue(result == null);
        }
    }
}
