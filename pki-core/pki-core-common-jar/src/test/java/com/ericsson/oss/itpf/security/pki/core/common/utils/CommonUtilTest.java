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
package com.ericsson.oss.itpf.security.pki.core.common.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayOutputStream;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CommonUtilTest {

    @InjectMocks
    private CommonUtil commonUtil;

    @Spy
    ByteArrayOutputStream byeArrayOutputStream;

    public static byte[] bytes = null;

    public static String sample = "Hello World";

    public static String deSerializedSample = null;

    /**
     * Method to test serialize and deSerialize of object.
     */
    @Test
    public void testSerializeAndDeserializeString() {
        bytes = CommonUtil.serializeObject(sample);
        deSerializedSample = (String) CommonUtil.deSerializeObject(bytes);
        assertNotNull(bytes);
        assertNotNull(deSerializedSample);
        assertEquals(sample, deSerializedSample);
    }
}
