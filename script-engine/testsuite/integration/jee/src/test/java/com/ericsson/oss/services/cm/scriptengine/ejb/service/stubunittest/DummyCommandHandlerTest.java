package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs.DummyCommandHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

public class DummyCommandHandlerTest {

    DummyCommandHandler objUnderTest = new DummyCommandHandler();

    @Test
    public void executeWithAliasErrorReturnsStatusMinusOne() {
        final Command command = new Command("dummy", "alias-error");
        final CommandResponseDto result = objUnderTest.execute(command);
        assertEquals(-1, result.getStatusCode());
    }

    @Test
    public void executeWithErrorReturnsStatusMinusOne() {
        final Command command = new Command("dummy", "error");
        final CommandResponseDto result = objUnderTest.execute(command);
        assertEquals(-1, result.getStatusCode());
    }

    @Test
    public void executeWithAliasReturnsStatusZero() {
        final Command command = new Command("dummy", "alias");
        final CommandResponseDto result = objUnderTest.execute(command);
        assertEquals(0, result.getStatusCode());
    }

    @Test
    public void executeWithWhoReturnUserIdAsStatusMessage() {
        final ContextServiceStubForUnitTest contextServiceStubForUnitTest = new ContextServiceStubForUnitTest();
        objUnderTest.setContextServiceStub(contextServiceStubForUnitTest);
        final Command command = new Command("dummy", "who");
        final CommandResponseDto result = objUnderTest.execute(command);
        assertEquals(0, result.getStatusCode());
        assertEquals(contextServiceStubForUnitTest.userId, result.getStatusMessage());
    }

    @Test
    public void executeWithAnyOtherCommandReturnsStatusZero() {
        final Command command = new Command("dummy", "any other command");
        final CommandResponseDto result = objUnderTest.execute(command);
        assertEquals(0, result.getStatusCode());
    }
}
