package com.ericsson.oss.services.cm.scriptengine.error

import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.cds.cdi.support.spock.CdiSpecification

import com.ericsson.oss.services.cm.error.ErrorManager
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandDto
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto


/**
 * Created by enmadmin on 10/18/21.
 */
class ErrorManagerSpec extends CdiSpecification {

    @ObjectUnderTest
    ErrorManager objUnderTest

    String command = "unknownCommandSet get * MeContext";


    def 'Unrecognized error generates error response '() {
        when: 'error manager call'
        CommandResponseDto result = objUnderTest.handleUnrecognisedCommand(command)

        then: 'check response fields'
            result.statusCode == ErrorHandlerImpl.UNEXPECTED_ERROR
            result.getErrorCode() == ErrorHandlerImpl.UNRECOGNISED_CLI_COMMAND_CODE
            result.responseDto.elements.contains(new CommandDto(command))
            result.getStatusMessage().startsWith(ErrorHandlerImpl.UNRECOGNISED_CLI_COMMAND_MSGS[0].substring(0,15))
            result.getSolution().equals(ErrorHandlerImpl.UNRECOGNISED_CLI_COMMAND_MSGS[1])
    }

    def 'DataBase Not available generates error response '() {
        when: 'errro manager call'
            CommandResponseDto result = objUnderTest.handleDatabaseNotAvailableException(command)

        then: 'check response fields'
            result.statusCode == ErrorHandlerImpl.UNEXPECTED_ERROR
            result.getErrorCode() == ErrorHandlerImpl.DATABASE_NOT_AVAILABLE_ERROR_CODE
            result.responseDto.elements.contains(new CommandDto(command))
            result.getStatusMessage().startsWith(ErrorHandlerImpl.DATABASE_NOT_AVAILABLE_ERROR_MSGS[0].substring(0,15))
            result.getSolution().equals(ErrorHandlerImpl.DATABASE_NOT_AVAILABLE_ERROR_MSGS[1])
    }

    def 'Exception generates error response '() {
        given: 'an exception'
            def errorMessage = "Exception error for test"
            def exception = new RuntimeException(errorMessage)
        when: 'errro manager call'
            CommandResponseDto result = objUnderTest.handleUnexpectedException(exception, command)

        then: 'check response fields'
            result.statusCode == ErrorHandlerImpl.UNEXPECTED_ERROR
            result.getErrorCode() == ErrorHandlerImpl.ERROR_CODE_UNEXPECTED_ERROR
            result.responseDto.elements.contains(new CommandDto(command))
            result.getStatusMessage().equals(ErrorHandlerImpl.EXCEPTION_MESSAGE + errorMessage)
    }

    def 'ReceiveNull Response from jms queue generates error response '() {
        when: 'errro manager call'
            CommandResponseDto result = objUnderTest.handleReceivingNullMessageFromQueue()

        then: 'check response fields'
            result.statusCode == ErrorHandlerImpl.UNEXPECTED_ERROR
            result.getErrorCode() == ErrorHandlerImpl.RECEIVED_NULL_MESSAGE_ERROR_CODE
            result.getStatusMessage().equals(ErrorHandlerImpl.RECEIVED_NULL_MESSAGE_ERROR_MSGS[0])
            result.getSolution().equals(ErrorHandlerImpl.RECEIVED_NULL_MESSAGE_ERROR_MSGS[1])
    }

    def 'UNAUTHORIZED command generates error response '() {
        when: 'errro manager call'
        CommandResponseDto result = objUnderTest.handleAccessUnauthorizedException()

        then: 'check response fields'
            result.statusCode == ErrorHandlerImpl.UNEXPECTED_ERROR
            result.getErrorCode() == ErrorHandlerImpl.ACCESS_UNAUTHORIZED_ERROR_CODE
            result.getStatusMessage().equals(ErrorHandlerImpl.ACCESS_UNAUTHORIZED_ERROR_MSGS[0])
            result.getSolution().equals(ErrorHandlerImpl.ACCESS_UNAUTHORIZED_ERROR_MSGS[1])
    }
}
