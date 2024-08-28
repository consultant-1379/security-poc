/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmhandler.handler.validation;

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

@RunWith(MockitoJUnitRunner.class)
public class CheckAutoupdateEnableDisableValidatorTest {

    @InjectMocks
    CheckAutoupdateEnableDisableValidator checkAutoupdateEnableDisableValidator;

    @Spy
    private final Logger logger = LoggerFactory.getLogger(CheckAutoupdateEnableDisableValidatorTest.class);


    final String AUTOUPDATE = "autoupdate";
    final PkiCommandType pkiCommandType = PkiCommandType.CONFIGMANAGEMENTCATEGORYUPDATE;

    @Test(expected = CommandSyntaxException.class)
    public void testValidate() {
        PkiPropertyCommand pkiCmdhandle = new PkiPropertyCommand();
        pkiCmdhandle.setCommandType(pkiCommandType);
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(AUTOUPDATE, "modify");
        pkiCmdhandle.setProperties(properties);
        checkAutoupdateEnableDisableValidator.validate(pkiCmdhandle);

    }

    @Test
    public void testValidate_enable() {
        PkiPropertyCommand pkiCmdhandle = new PkiPropertyCommand();
        pkiCmdhandle.setCommandType(pkiCommandType);
        final Map<String, Object> properties = new HashMap<String, Object>();
        properties.put(AUTOUPDATE, "enable");
        pkiCmdhandle.setProperties(properties);
        checkAutoupdateEnableDisableValidator.validate(pkiCmdhandle);

    }

}
