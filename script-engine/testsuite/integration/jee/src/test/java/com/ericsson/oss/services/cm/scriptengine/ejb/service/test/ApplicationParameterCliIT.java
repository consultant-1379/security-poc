/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.services.cm.scriptengine.ejb.service.test;

import static com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest.NodePluginAndConfigurationMockServer.Expectation.*;
import static org.junit.Assert.assertTrue;
import static org.mockserver.verify.VerificationTimes.atLeast;
import static org.mockserver.verify.VerificationTimes.once;

import javax.inject.Inject;

import org.jboss.arquillian.container.test.api.OperateOnDeployment;
import org.jboss.arquillian.junit.Arquillian;
import org.junit.Test;
import org.jboss.arquillian.junit.InSequence;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs.ApplicationParameterCliProxy;
import com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest.NodePluginAndConfigurationMockServer;
import com.ericsson.oss.services.scriptengine.spi.CommandHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.Command;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

@RunWith(Arquillian.class)
public class ApplicationParameterCliIT extends ScriptEngineTestBase {

    private static final int PORT = 1234;
    private static final String PROTOCOL = "http";
    private static final String HOSTNAME = "localhost";
    private static final String INTERNAL_URL = "INTERNAL_URL";

    private static final Logger logger = LoggerFactory.getLogger(ApplicationParameterCliIT.class);

    @Inject
    ApplicationParameterCliProxy applicationParameterCliProxy;

    static {
        System.setProperty(INTERNAL_URL, PROTOCOL + "://" + HOSTNAME + ":" + PORT);
    }

    @Test
    @InSequence(1)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminViewAllParametersWithAuthorizedUser() {
        final NodePluginAndConfigurationMockServer nodePluginAndConfigurationMockServer = new NodePluginAndConfigurationMockServer(PORT);

        asAuthorizedUser();

        nodePluginAndConfigurationMockServer.createExpectation(ADMIN_PARAMETER_VIEW_SUCC);

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();

        final Command command = new Command("admin", "parameter view");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        nodePluginAndConfigurationMockServer.verify(ADMIN_PARAMETER_VIEW_SUCC.getRequest(), once());
        assertTrue("command in response is not as expected", response.getCommand().equalsIgnoreCase("admin"));
        assertTrue("status code in response is not as expected", response.getStatusCode() == 0);

        nodePluginAndConfigurationMockServer.stop();
    }

    @Test
    @InSequence(2)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminModifySnmpWithAuthorizedUser() {
        final NodePluginAndConfigurationMockServer nodePluginAndConfigurationMockServer = new NodePluginAndConfigurationMockServer(PORT);

        asAuthorizedUser();

        nodePluginAndConfigurationMockServer.createExpectation(MODIFY_PARAM_AP_SNMP_AUDIT_TIME_SUCC);

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();
        final Command command = new Command("admin",
                "parameter modify --name AP_SNMP_AUDIT_TIME --value 12:30");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        nodePluginAndConfigurationMockServer.verify(MODIFY_PARAM_AP_SNMP_AUDIT_TIME_SUCC.getRequest(), atLeast(1));
        assertTrue("command in response is not as expected", response.getCommand().equalsIgnoreCase("admin"));
        assertTrue("status code in response is not as expected", response.getStatusCode() == 0);

        nodePluginAndConfigurationMockServer.stop();
    }

    @Test
    @InSequence(2)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminModifyNonSnmpWithAuthorizedUser() {
        final NodePluginAndConfigurationMockServer nodePluginAndConfigurationMockServer = new NodePluginAndConfigurationMockServer(PORT);

        asAuthorizedUser();

        nodePluginAndConfigurationMockServer.createExpectation(MODIFY_PARAM_PMIC_SUPPORTED_ROP_PERIODS_SUCC);

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();
        final Command command = new Command("admin",
                "parameter modify --name pmicSupportedRopPeriods --value [ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR]");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        nodePluginAndConfigurationMockServer.verify(MODIFY_PARAM_PMIC_SUPPORTED_ROP_PERIODS_SUCC.getRequest(), atLeast(1));
        assertTrue("command in response is not as expected", response.getCommand().equalsIgnoreCase("admin"));
        assertTrue("status code in response is not as expected", response.getStatusCode() == 0);

        nodePluginAndConfigurationMockServer.stop();
    }

    @Test
    @InSequence(3)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminViewCliWithUnauthorizedUser() {

        asUnauthorizedUser();

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();
        final Command command = new Command("admin", "parameter view");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        assertTrue("status code in response is not as expected", response.getStatusCode() == -2);
        assertTrue("error code in response is not as expected", response.getErrorCode() == 6018);
    }

    @Test
    @InSequence(4)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminModifySnmpCliWithUnauthorizedUser() {

        asUnauthorizedUser();

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();
        final Command command = new Command("admin",
                "parameter modify --name NODE_SNMP_INIT_SECURITY --value {securityLevel:AUTH_PRIV,authPassword:onlytset,authProtocol:MD5,privPassword:onlytest,privProtocol:AES128,user:newuserprefix}");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        assertTrue("status code in response is not as expected", response.getStatusCode() == -2);
        assertTrue("error code in response is not as expected", response.getErrorCode() == 6018);
    }

    @Test
    @InSequence(5)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminModifyNonSnmpCliWithUnauthorizedUser() {

        asUnauthorizedUser();

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();
        final Command command = new Command("admin",
                "parameter modify --name pmicSupportedRopPeriods --value [ONE_MIN,FIVE_MIN,FIFTEEN_MIN,THIRTY_MIN,ONE_HOUR,TWELVE_HOUR]");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        assertTrue("status code in response is not as expected", response.getStatusCode() == -2);
        assertTrue("error code in response is not as expected", response.getErrorCode() == 6018);
    }

    @Test
    @InSequence(6)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminViewServiceScopedParametersWithAuthorizedUser() {
        final NodePluginAndConfigurationMockServer nodePluginAndConfigurationMockServer = new NodePluginAndConfigurationMockServer(PORT);

        asAuthorizedUser();

        nodePluginAndConfigurationMockServer.createExpectation(ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_SUCC);

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();

        final Command command = new Command("admin", "parameter view --service_identifier ap-workflow-vnf --all");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        nodePluginAndConfigurationMockServer.verify(ADMIN_PARAMETER_VIEW_SERVICE_SCOPED_SUCC.getRequest(), once());
        assertTrue("command in response is not as expected", response.getCommand().equalsIgnoreCase("admin"));
        assertTrue("status code in response is not as expected", response.getStatusCode() == 0);

        nodePluginAndConfigurationMockServer.stop();
    }

    @Test
    @InSequence(7)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminViewJvmScopedParametersWithAuthorizedUser() {
        final NodePluginAndConfigurationMockServer nodePluginAndConfigurationMockServer = new NodePluginAndConfigurationMockServer(PORT);

        asAuthorizedUser();

        nodePluginAndConfigurationMockServer.createExpectation(ADMIN_PARAMETER_VIEW_JVM_SCOPED_SUCC);

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();

        final Command command = new Command("admin", "parameter view --app_server_identifier ap-workflow-vnf --all");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        nodePluginAndConfigurationMockServer.verify(ADMIN_PARAMETER_VIEW_JVM_SCOPED_SUCC.getRequest(), once());
        assertTrue("command in response is not as expected", response.getCommand().equalsIgnoreCase("admin"));
        assertTrue("status code in response is not as expected", response.getStatusCode() == 0);

        nodePluginAndConfigurationMockServer.stop();
    }

    @Test
    @InSequence(8)
    @OperateOnDeployment(EAP7_DEPLOYMENT)
    public void executeAdminViewServiceAndJvmScopedParametersWithAuthorizedUser() {
        final NodePluginAndConfigurationMockServer nodePluginAndConfigurationMockServer = new NodePluginAndConfigurationMockServer(PORT);

        asAuthorizedUser();

        nodePluginAndConfigurationMockServer.createExpectation(ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_SUCC);

        final CommandHandler applicationParameterCli = applicationParameterCliProxy.getApplicationParameterCli();

        final Command command = new Command("admin", "parameter view --service_identifier ap-workflow-vnf --app_server_identifier ap-workflow-vnf --all");

        final CommandResponseDto response = applicationParameterCli.execute(command);

        if (logger.isInfoEnabled()) {
            logger.info("CommandResponseDto: {}", response.getResponseDto());
        }

        nodePluginAndConfigurationMockServer.verify(ADMIN_PARAMETER_VIEW_SERVICE_AND_JVM_SCOPED_SUCC.getRequest(), once());
        assertTrue("command in response is not as expected", response.getCommand().equalsIgnoreCase("admin"));
        assertTrue("status code in response is not as expected", response.getStatusCode() == 0);

        nodePluginAndConfigurationMockServer.stop();
    }
}
