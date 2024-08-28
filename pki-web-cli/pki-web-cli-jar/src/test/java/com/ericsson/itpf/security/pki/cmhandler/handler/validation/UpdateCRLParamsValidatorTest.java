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
package com.ericsson.itpf.security.pki.cmhandler.handler.validation;

import static org.junit.Assert.*;

import java.util.*;

import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;

@RunWith(MockitoJUnitRunner.class)
public class UpdateCRLParamsValidatorTest {

    @InjectMocks
    UpdateCRLParamsValidator updateCRLParamsValidator = new UpdateCRLParamsValidator();

    @Spy
    private final Logger logger = LoggerFactory.getLogger(UpdateCRLParamsValidatorTest.class);

    static PkiPropertyCommand pkiCmdhandle;

    static Set<String> optionalServiceKeys;

    @BeforeClass
    public static void initialize() {
        pkiCmdhandle = new PkiPropertyCommand();
        pkiCmdhandle.setCommandType(PkiCommandType.EXTERNALCAUPDATECRL);
    }

    @Test
    public void testValidateUpdateFromUrl() {
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("url", "urlPath");
        properties.put("name", "CAname");
        pkiCmdhandle.setProperties(properties);
        assertTrue(updateCRLParamsValidator.validateKeys(pkiCmdhandle, UpdateCRLParamsValidator.expectedUpdateCRLUrlKeys));
    }

    @Test
    public void testValidateUpdateFromFile() {
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put("command", PkiCommandType.EXTERNALCACERTIMPORT);
        properties.put("filePath", "path");
        properties.put("name", "CAname");
        properties.put("filename", "test");
        properties.put("fileName", "test");
        properties.put("filePath", "test");
        pkiCmdhandle.setProperties(properties);
        assertTrue(updateCRLParamsValidator.validateKeys(pkiCmdhandle, UpdateCRLParamsValidator.expectedUpdateCRLFileKeys));
    }
}
