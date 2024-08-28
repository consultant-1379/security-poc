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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import static org.junit.Assert.*;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidExtendedKeyUsageException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidKeyUsageException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class ExtendedKeyUsageBuilderTest extends BaseTest {

    @InjectMocks
    private ExtendedKeyUsageBuilder extendedKeyUsageBuilder;

    private ExtendedKeyUsage extendedKeyUsage;
    private Extension extendedKeyUsageActual;
    private List<KeyPurposeId> keyPurposeId;

    /**
     * Prepares initial data.
     * 
     * @throws Exception
     *             {@link IOException}
     */
    @Before
    public void setUp() throws Exception {
        extendedKeyUsage = new ExtendedKeyUsage();
        extendedKeyUsage.setCritical(true);

        keyPurposeId = new ArrayList<KeyPurposeId>();
        keyPurposeId.add(KeyPurposeId.ID_KP_CLIENT_AUTH);
        keyPurposeId.add(KeyPurposeId.ID_KP_CODE_SIGNING);
        keyPurposeId.add(KeyPurposeId.ANY_EXTENDED_KEY_USAGE);
        keyPurposeId.add(KeyPurposeId.ID_KP_EMAIL_PROTECTION);
        keyPurposeId.add(KeyPurposeId.ID_KP_OCSP_SIGNING);
        keyPurposeId.add(KeyPurposeId.ID_KP_SERVER_AUTH);
        keyPurposeId.add(KeyPurposeId.ID_KP_TIME_STAMPING);

        extendedKeyUsage.setSupportedKeyPurposeIds(keyPurposeId);
    }

    /**
     * Method to test building of {@link ExtendedKeyUsage} extension
     * 
     * @throws IOException
     */
    @Test
    public void testBuildExtendedKeyUsage() throws IOException {
        extendedKeyUsageActual = extendedKeyUsageBuilder.buildExtendedKeyUsage(extendedKeyUsage);

        final DEROctetString extendedKeyUsageExpected = new DEROctetString(getExtendedKeyUsage(extendedKeyUsage.getSupportedKeyPurposeIds()));

        assertExtensionValue(extendedKeyUsageExpected, extendedKeyUsageActual);
        assertEquals(Extension.extendedKeyUsage, extendedKeyUsageActual.getExtnId());
    }

    /**
     * Method to test building of {@link ExtendedKeyUsage} with empty list.
     */
    @Test
    public void testBuildExtendedKeyUsageWithEmptyList() {
        keyPurposeId.clear();

        extendedKeyUsageActual = extendedKeyUsageBuilder.buildExtendedKeyUsage(extendedKeyUsage);

        assertNull(extendedKeyUsageActual);
    }

    private org.bouncycastle.asn1.x509.ExtendedKeyUsage getExtendedKeyUsage(final List<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId> keyPurposeData)
            throws InvalidExtendedKeyUsageException {
        try {
            org.bouncycastle.asn1.x509.KeyPurposeId[] keyPurposeIds1 = new org.bouncycastle.asn1.x509.KeyPurposeId[keyPurposeData.size()];
            for (int i = 0; i < keyPurposeData.size(); i++) {
                Field field;
                field = org.bouncycastle.asn1.x509.KeyPurposeId.class.getDeclaredField(keyPurposeData.get(i).getValue());

                keyPurposeIds1[i] = (org.bouncycastle.asn1.x509.KeyPurposeId) field.get(null);

            }
            final org.bouncycastle.asn1.x509.ExtendedKeyUsage extendedKeyUsage = new org.bouncycastle.asn1.x509.ExtendedKeyUsage(keyPurposeIds1);
            return extendedKeyUsage;
        } catch (IllegalAccessException illegalAccessException) {
            logger.error(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION, illegalAccessException);
            throw new InvalidKeyUsageException(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION);
        } catch (NoSuchFieldException noSuchFieldException) {
            logger.error(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION, noSuchFieldException);
            throw new InvalidKeyUsageException(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION);
        }
    }
}
