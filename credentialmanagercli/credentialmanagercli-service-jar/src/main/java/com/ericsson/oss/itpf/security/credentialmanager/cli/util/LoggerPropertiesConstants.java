/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.util;

public interface LoggerPropertiesConstants {
    String LOG_DEBUG_START_APP = "log.debug.start.app";
    String LOG_DEBUG_END_APP = "log.debug.end.app";
    String LOG_DEBUG_APP = "log.debug.app";
    String LOG_ERROR_APP = "log.error.app";

    String LOG_INFO_PARSE_START_COMMANDS = "log.info.parse.start.commands";
    String LOG_INFO_PARSE_END_COMMANDS = "log.info.parse.end.commands";
    String LOG_ERROR_PARSE_COMMANDS = "log.error.parse.commands";
    String LOG_DEBUG_PARSE_COMMANDS = "log.debug.parse.commands";

    String LOG_INFO_VALIDATE_START_COMMANDS = "log.info.validate.start.commands";
    String LOG_INFO_VALIDATE_END_COMMANDS = "log.info.validate.end.commands";
    String LOG_ERROR_VALIDATE_COMMANDS = "log.error.validate.commands";
    String LOG_DEBUG_VALIDATE_COMMANDS = "log.debug.validate.commands";

    String LOG_INFO_EXECUTE_START_COMMAND = "log.info.execute.start.command";
    String LOG_INFO_EXECUTE_END_COMMAND = "log.info.execute.end.command";
    String LOG_INFO_EXECUTE_FIRST_DAILY_RUN = "log.info.execute.first.daily.run";

    String LOG_INFO_READ_START_APPFILE = "log.info.read.start.appfile";
    String LOG_INFO_READ_END_APPFILE = "log.info.read.end.appfile";
    String LOG_ERROR_READ_APPFILE = "log.error.read.appfile";
    String LOG_DEBUG_READ_APPFILE = "log.debug.read.appfile";
    
    String LOG_INFO_READ_START_APPPATH = "log.info.read.start.apppath";
    String LOG_INFO_READ_END_APPPATH = "log.info.read.end.apppath";
    String LOG_ERROR_READ_APPPATH = "log.error.read.apppath";
    String LOG_DEBUG_READ_APPPATH = "log.debug.read.apppath";
    
    
    String LOG_DEBUG_CONNECT_START_EEMANAGER = "log.debug.connect.start.eemanager";
    String LOG_DEBUG_CONNECT_END_EEMANAGER = "log.debug.connect.end.eemanager";
    String LOG_ERROR_CONNECT_EEMANAGER = "log.error.connect.eemanager";
    String LOG_DEBUG_CONNECT_EEMANAGER = "log.debug.connect.eemanager";

    String LOG_DEBUG_CREATE_START_EE = "log.debug.create.start.ee";
    String LOG_DEBUG_CREATE_END_EE = "log.debug.create.end.ee";
    String LOG_ERROR_CREATE_EE = "log.error.create.ee";
    String LOG_DEBUG_CREATE_EE = "log.debug.create.start.ee";

    String LOG_DEBUG_CREATE_START_KEYPAIR = "log.debug.create.start.keypair";
    String LOG_DEBUG_CREATE_END_KEYPAIR = "log.debug.create.end.keypair";
    String LOG_ERROR_CREATE_KEYPAIR = "log.error.create.keypair";
    String LOG_DEBUG_CREATE_KEYPAIR = "log.debug.create.keypair";
    String LOG_DEBUG_CREATE_KEYPAIR_ALGORITHM = "log.debug.create.keypair.algorithm";
    String LOG_DEBUG_CREATE_KEYPAIR_SIZE = "log.debug.create.keypair.size";

    String LOG_INFO_CREATE_START_CSR = "log.info.create.start.csr";
    String LOG_INFO_CREATE_END_CSR = "log.info.create.end.csr";
    String LOG_ERROR_CREATE_CSR = "log.error.create.csr";
    String LOG_DEBUG_CREATE_CSR = "log.debug.create.csr";
    String LOG_DEBUG_CREATE_CSR_ALGORITHM = "log.debug.create.csr.algorithm";
    String LOG_DEBUG_CREATE_CSR_SUBJECT = "log.debug.create.csr.subject";

    String LOG_DEBUG_CREATE_START_CSRHOLDER = "log.debug.create.start.csrholder";
    String LOG_DEBUG_CREATE_END_CSRHOLDER = "log.debug.create.end.csrholder";
    String LOG_ERROR_CREATE_CSRHOLDER = "log.error.create.csrholder";
    String LOG_DEBUG_CREATE_CSRHOLDER = "log.debug.create.csrholder";

    String LOG_DEBUG_CONNECT_START_RAMANAGER = "log.debug.connect.start.ramanager";
    String LOG_DEBUG_CONNECT_END_RAMANAGER = "log.debug.connect.end.ramanager";
    String LOG_ERROR_CONNECT_RAMANAGER = "log.error.connect.ramanager";
    String LOG_DEBUG_CONNECT_RAMANAGER = "log.debug.connect.ramanager";

    String LOG_DEBUG_SEND_START_CSR = "log.debug.send.start.csr";
    String LOG_DEBUG_SEND_END_CSR = "log.debug.send.end.csr";
    String LOG_ERROR_SEND_CSR = "log.error.send.csr";
    String LOG_DEBUG_SEND_CSR = "log.debug.send.csr";

    String LOG_INFO_CREATE_START_CERTIFICATE = "log.info.create.start.certificate";
    String LOG_INFO_CREATE_END_CERTIFICATE = "log.info.create.end.certificate";
    String LOG_ERROR_CREATE_CERTIFICATE = "log.error.create.certificate";
    String LOG_DEBUG_CREATE_CERTIFICATE = "log.debug.create.certificate";

    String LOG_DEBUG_CONNECT_START_CAMANAGER = "log.debug.connect.start.camanager";
    String LOG_DEBUG_CONNECT_END_CAMANAGER = "log.debug.connect.end.camanager";
    String LOG_ERROR_CONNECT_CAMANAGER = "log.error.connect.camanager";
    String LOG_DEBUG_CONNECT_CAMANAGER = "log.debug.connect.camanager";

    String LOG_INFO_GET_START_CA = "log.info.get.start.ca";
    String LOG_INFO_GET_END_CA = "log.info.get.end.ca";
    String LOG_ERROR_GET_CA = "log.error.get.ca";
    String LOG_DEBUG_GET_CA = "log.debug.get.ca";

    String LOG_INFO_CREATE_START_KEYSTORE = "log.info.create.start.keystore";
    String LOG_INFO_CREATE_END_KEYSTORE = "log.info.create.end.keystore";
    String LOG_ERROR_CREATE_KEYSTORE = "log.error.create.keystore";
    String LOG_DEBUG_CREATE_KEYSTORE = "log.debug.create.keystore";
    String LOG_INFO_EXIST_KEYSTORE = "log.info.exist.keystore";

    String LOG_INFO_CREATE_START_TRUSTSTORE = "log.info.create.start.truststore";
    String LOG_INFO_CREATE_END_TRUSTSTORE = "log.info.create.end.truststore";
    String LOG_ERROR_CREATE_TRUSTSTORE = "log.error.create.truststore";
    String LOG_DEBUG_CREATE_TRUSTSTORE = "log.debug.create.truststore";
    String LOG_INFO_EXIST_TRUSTSTORE = "log.info.exist.truststore";

    String LOG_ERROR_READ_PROPERTIES_FILE = "log.error.read.propertiesfile";
    String LOG_ERROR_READ_XSD_FILE = "log.error.read.xsdfile";
    String LOG_ERROR_CREATE_KSTS = "log.error.create.ksts";
    String LOG_ERROR_COMMANDS_INVALIDE = "log.error.commands.invalide";

    String LOG_INFO_ISSUECERTIFICATE = "log.info.send.issueCertificate";
    String LOG_DEBUG_ISSUECERTIFICATE_START = "log.debug.send.issueCertificate.start";
    String LOG_DEBUG_ISSUECERTIFICATE_END = "log.debug.send.issueCertificate.end";

    String LOG_ERROR_GETTING_MY_CERTIFICATE = "log.error.mycertificate";
    String LOG_INFO_GETTING_MY_CERTIFICATE_START = "log.info.mycertificate.start";
    String LOG_INFO_GETTING_MY_CERTIFICATE_OK = "log.info.mycertificate.noneedto";
    String LOG_INFO_GETTING_MY_CERTIFICATE_SUCCESS = "log.info.mycertificate.success";
    String LOG_INFO_GETTING_MY_CERTIFICATE_END = "log.info.mycertificate.end";
    String LOG_DEBUG_GETTING_MY_CERTIFICATE_XMLMISS = "log.debug.mycertificate.xmlmissing";
    String LOG_DEBUG_GETTING_MY_CERTIFICATE_XMLPARSE = "log.debug.mycertificate.xmlparsing";
    String LOG_DEBUG_GETTING_MY_CERTIFICATE_GETCERT = "log.debug.mycertificate.notretrieve";
    String LOG_INFO_GETTING_CERTIFICATE_ERR = "log.error.certificate.invalid";
    String LOG_INFO_GETTING_CERTIFICATE_OK = "log.info.certificate.noneedto";

    String LOG_DEBUG_CLICERTIFICATE = "log.debug.send.checkCertificateForCLI";
    String LOG_INFO_CLICERTIFICATE = "log.info.send.issueCertificateForCLI";

    String LOG_DEBUG_CLICHECK = "log.debug.send.clicheck";
    String LOG_INFO_CLICHECK = "log.info.send.clicheck";
}
