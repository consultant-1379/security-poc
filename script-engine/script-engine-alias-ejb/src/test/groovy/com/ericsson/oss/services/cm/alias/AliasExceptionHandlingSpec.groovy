package com.ericsson.oss.services.cm.alias

import com.ericsson.cds.cdi.support.rule.ImplementationClasses
import com.ericsson.cds.cdi.support.rule.MockedImplementation
import com.ericsson.cds.cdi.support.rule.ObjectUnderTest
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.itpf.datalayer.dps.DataBucket
import com.ericsson.oss.itpf.datalayer.dps.DataPersistenceService
import com.ericsson.oss.itpf.datalayer.dps.query.Query
import com.ericsson.oss.itpf.datalayer.dps.query.QueryBuilder
import com.ericsson.oss.itpf.datalayer.dps.query.QueryExecutor
import com.ericsson.oss.itpf.datalayer.dps.query.Restriction
import com.ericsson.oss.itpf.datalayer.dps.query.TypeRestrictionBuilder
import com.ericsson.oss.itpf.sdk.context.ContextService
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef
import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean
import com.ericsson.oss.itpf.sdk.eventbus.ChannelLocator
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder
import com.ericsson.oss.services.cm.alias.events.dps.DatabaseStatus
import com.ericsson.oss.services.cm.alias.exceptions.CannotFindAliasException
import com.ericsson.oss.services.cm.alias.exceptions.CannotPersistAliasException
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl
import com.ericsson.oss.services.cm.error.exception.DatabaseNotAvailableException
import com.ericsson.oss.services.scriptengine.api.ServiceFinderBeanProvider
import com.ericsson.oss.services.scriptengine.spi.CommandHandler
import com.ericsson.oss.services.scriptengine.spi.dtos.Command

import javax.inject.Inject

/**
 * Tests with mocked DPS for exception handling.
 */
class AliasExceptionHandlingSpec extends CdiSpecification {

    @ObjectUnderTest
    AliasHandler objUnderTest

    @ImplementationClasses
    def classes = [ErrorHandlerImpl]

    @Inject
    ContextService contextServiceMock

    @Inject
    SystemRecorder systemRecorderMock

    @Inject
    AliasDao aliasDao

    @Inject
    ChannelLocator channelLocatorMock

    @MockedImplementation
    @EServiceRef
    DataPersistenceService dpsMock

    @MockedImplementation
    DataBucket dataBucket

    @MockedImplementation
    ServiceFinderBeanProvider serviceFinderBeanProviderMock

    @MockedImplementation
    DatabaseStatus databaseStatusMock

    def serviceFinderBeanMock = Mock(ServiceFinderBean)
    def dataBucketMock = [ getQueryExecutor: {
        [ execute: {
            [].iterator()
        }] as QueryExecutor
    }] as DataBucket
    def restrictionBuilderMock = Mock(TypeRestrictionBuilder)
    def typeQuery = [ getRestrictionBuilder: { restrictionBuilderMock }, setRestriction: { Restriction restriction -> }] as Query
    def queryBuilderMock = [ createTypeQuery: { String namespace, String type ->  typeQuery } ] as QueryBuilder

    def setup() {
        serviceFinderBeanProviderMock.getServiceFinderBean() >> serviceFinderBeanMock
        serviceFinderBeanMock.findAll(CommandHandler, _ as String) >> []
        dpsMock.getQueryBuilder() >> queryBuilderMock
        databaseStatusMock.isAvailable() >> true
    }

    def 'create alias, with error in create, throws CannotPersistAliasException'() {
        given: 'an alias create command'
            def command = new Command('alias', '"aliasName $1" "commandSet arg1 $1"', [:])

        when: 'execute command to create alias'
            objUnderTest.execute(command)

        then: 'the calls to getLiveBucket throw an exception on the second call'
            2 * dpsMock.getLiveBucket() >>> [dataBucketMock, { throw new Exception() }]

        and: 'the correct exception is thrown'
            thrown CannotPersistAliasException
    }

    def 'check if is alias, with error in search, throws CannotFindAliasException'() {
        given: 'a command'
            def command = new Command('command', 'with arguments', [:])

        when: 'check if command is an alias'
            objUnderTest.isAlias(command)

        then: 'the call to getLiveBucket throws an exception'
            1 * dpsMock.getLiveBucket() >> { throw new Exception() }

        and: 'the correct exception is thrown'
            thrown CannotFindAliasException
    }

    def 'create alias, when database is unavailable, throws DatabaseNotAvailableException'() {
        given: 'an alias create command'
            def command = new Command('alias', '"aliasName $1" "commandSet arg1 $1"', [:])

        when: 'execute command to create alias'
            objUnderTest.execute(command)

        then: 'the database is not available on second check'
            1 * databaseStatusMock.isAvailable() >> false

        and: 'the correct exception is thrown'
            thrown DatabaseNotAvailableException
    }

    def 'check if is alias, when database is unavailable, throws DatabaseNotAvailableException'() {
        given: 'a command'
            def command = new Command('command', 'with arguments', [:])

        when: 'check if command is an alias'
            objUnderTest.isAlias(command)

        then: 'the database is not available on second check'
            1 * databaseStatusMock.isAvailable() >> false

        and: 'the correct exception is thrown'
            thrown DatabaseNotAvailableException
    }
}
