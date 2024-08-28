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
package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.entities.api.EntityConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.entities.impl.AppEntityXmlConfiguration;
import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

public class PkiCAEntityMapperTest {

    @Test
    public void testFakeConstructor() { 
        Constructor<PkiCAEntityMapper> constructor;
        try {
            constructor = PkiCAEntityMapper.class.getDeclaredConstructor();

            constructor.setAccessible(true);
            PkiCAEntityMapper pkiCA = constructor.newInstance();
            assertTrue(pkiCA != null);
        } catch (NoSuchMethodException | SecurityException | InstantiationException | 
                IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            assertTrue(false);
        }
    }
    
    /**
     * Test method for {@link com.ericsson.oss.itpf.security.credmservice.util.PkiCAEntityMapper#ConvertEntityFrom(com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity)} .
     */
    @Test
    public void testConvertEntityFrom1() {
        final File xmlPathTest = new File("src/test/resources/caEntities.xml");

        EntityConfigInformation caEntityConfigInfo = null;

        try {
            caEntityConfigInfo = new AppEntityXmlConfiguration(xmlPathTest);
        } catch (final CredentialManagerEntitiesException e) {
            System.out.println(e.getCause());
            assertTrue(false);
        }

        assertTrue("entityConfigInfo is NULL", caEntityConfigInfo != null);

        CAEntity caEntity = null;
        try {
            caEntity = PkiCAEntityMapper.ConvertEntityFrom(caEntityConfigInfo.getCAEntitiesInfo().get(1));

        } catch (final PkiEntityMapperException e) {
            System.out.println(e.getCause());
            assertTrue(false);
        }

        assertTrue("Wrong CAEntity Name", caEntity.getCertificateAuthority().getName().equals("ENM_Infrastructure_CA"));

        assertTrue("Wrong KeyGenerationAlgorithm Name", caEntity.getKeyGenerationAlgorithm().getName().equals("RSA"));

        assertTrue("Wrong KeyGenerationAlgorithm KeySize", caEntity.getKeyGenerationAlgorithm().getKeySize() == 2048);

        assertTrue("Wrong CRL Version", caEntity.getCertificateAuthority().getCrlGenerationInfo().get(0).getVersion().value() == 2);

        assertTrue("Wrong Skew Crl Time", caEntity.getCertificateAuthority().getCrlGenerationInfo().get(0).getSkewCrlTime().toString().equalsIgnoreCase("PT30M"));

        assertTrue("Wrong Skew Crl Time", caEntity.getCertificateAuthority().getCrlGenerationInfo().get(0).getSkewCrlTime().getMinutes() == 30);

        //assertTrue("Wrong CACRLSignatureAlgorithm Name", caEntity.getcACRL().getcRLSignatureAlgorithm().getName().equals("SHA256withRSA"));

        //assertTrue("Wrong CACRLSignatureAlgorithm KeySize ", caEntity.getcACRL().getcRLSignatureAlgorithm().getKeySize() == 2048);

    }

    @Test
    public void testConvertEntityFrom2() {
        final File xmlPathTest = new File("src/test/resources/ENM-PKI-Root-CA.xml");

        EntityConfigInformation caEntityConfigInfo = null;

        try {
            caEntityConfigInfo = new AppEntityXmlConfiguration(xmlPathTest);
        } catch (final CredentialManagerEntitiesException e) {
            System.out.println(e.getCause());
            assertTrue(false);
        }

        assertTrue("entityConfigInfo is NULL", caEntityConfigInfo != null);

        CAEntity caEntity = null;
        try {
            caEntity = PkiCAEntityMapper.ConvertEntityFrom(caEntityConfigInfo.getCAEntitiesInfo().get(0));

        } catch (final PkiEntityMapperException e) {
            System.out.println(e.getCause());
            assertTrue(false);
        }

        assertTrue("Wrong CAEntity Name", caEntity.getCertificateAuthority().getName().equals("ENM PKI Root CA"));

        assertTrue("Wrong RootCA", caEntity.getCertificateAuthority().isRootCA());

        assertTrue("Wrong Publish CRL to CDPS", caEntity.getCertificateAuthority().isPublishToCDPS() == true);

        assertTrue("CRL Number is critical !", caEntity.getCertificateAuthority().getCrlGenerationInfo().get(0).getCrlExtensions().getCrlNumber().isCritical() == false);

        assertTrue("CRL Autorithy Key Identifier is Critical !", caEntity.getCertificateAuthority().getCrlGenerationInfo().get(0).getCrlExtensions().getAuthorityKeyIdentifier().isCritical() == false);

        //assertTrue("Wrong CACRLSignatureAlgorithm Name", caEntity.getcACRL().getcRLSignatureAlgorithm().getName().equals("SHA256withDSA"));

        //assertTrue("Wrong getSkewCRLTime", caEntity.getcACRL().getSkewCRLTime().equals("10"));

    }
    
    @Test
    public void testConvertEntityFromNull() {
        
        CAEntity caEntity = null;
        try {
            caEntity = PkiCAEntityMapper.ConvertEntityFrom(null);
        } catch (PkiEntityMapperException e) {
            assertTrue(caEntity == null);
        }        
        
    }

}
