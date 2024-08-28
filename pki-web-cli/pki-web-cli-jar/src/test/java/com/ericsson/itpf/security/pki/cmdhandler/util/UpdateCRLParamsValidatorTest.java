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
package com.ericsson.itpf.security.pki.cmdhandler.util;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.UpdateCRLParamsValidator;


@RunWith(MockitoJUnitRunner.class)
public class UpdateCRLParamsValidatorTest {

    @InjectMocks
    UpdateCRLParamsValidator updateCRL = new UpdateCRLParamsValidator();

    static PkiPropertyCommand pkiCmdhandle;

    @Spy
    private final Logger logger = LoggerFactory.getLogger(UpdateCRLParamsValidatorTest.class);

    @Test
    public void testValidateArgumentWithFile() {
        logger.debug("executing testValidateAlgorithmIsCorrect");
        pkiCmdhandle = new PkiPropertyCommand();

        pkiCmdhandle.setCommandType(PkiCommandType.EXTERNALCAUPDATECRL);
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(UpdateCRLParamsValidator.CA_NAME, "CAName");
        properties.put(UpdateCRLParamsValidator.FILE_NAME, "myFile");

        pkiCmdhandle.setProperties(properties);

        updateCRL.validate(pkiCmdhandle);
    }

    @Test
    public void testValidateArgumentWithUrl() {
        logger.debug("executing testValidateAlgorithmIsCorrect");
        pkiCmdhandle = new PkiPropertyCommand();

        pkiCmdhandle.setCommandType(PkiCommandType.EXTERNALCAUPDATECRL);
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(UpdateCRLParamsValidator.CA_NAME, "CAName");
        properties.put(UpdateCRLParamsValidator.URL, "https/myURL");
        properties.put(UpdateCRLParamsValidator.FILE_NAME, null);

        pkiCmdhandle.setProperties(properties);

        updateCRL.validate(pkiCmdhandle);
    }

    @Test(expected = CommandSyntaxException.class)
    public void testValidateParameterIsWrong() {
        pkiCmdhandle = new PkiPropertyCommand();

        pkiCmdhandle.setCommandType(PkiCommandType.EXTERNALCAUPDATECRL);
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(UpdateCRLParamsValidator.FILE_NAME, "myFile");
        properties.put(UpdateCRLParamsValidator.URL, "https/myURL");

        pkiCmdhandle.setProperties(properties);

        updateCRL.validate(pkiCmdhandle);
    }


}
