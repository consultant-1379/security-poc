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
package com.ericsson.oss.itpf.security.credentialmanager.cli.implementation;

import java.io.File;
import java.util.*;

import org.apache.commons.cli.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.api.Command;
import com.ericsson.oss.itpf.security.credentialmanager.cli.api.CommandParser;
import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.Logger;
import com.ericsson.oss.itpf.security.credentialmanager.cli.util.PropertiesReader;

//TODO To map the command properties to constants
/**
 * CommandParserImpl
 * 
 * @implements CommandParser
 * @author enmadmin
 *
 */
public class CommandParserImpl implements CommandParser {
    /**
     * 
     */
    // TORF-562254 update log4j
    private static final org.apache.logging.log4j.Logger LOG = Logger.getLogger();

    private final Properties configProperties = PropertiesReader.getConfigProperties();
    private final Properties commandProperties = PropertiesReader.getProperties(this.configProperties.getProperty("commands"));
    

    @Override
    public Command parse(final String[] args) {
        Command command = null;
        final Options optionsFlag = this.buildCommandsFlags(this.commandProperties);
        final CommandLine line = this.getCommandsParsed(optionsFlag, args);

        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_START_COMMANDS));

// MUNGE CONDITIONAL TAG
/*if[TEST_COMMAND]
        LOG.info("... CredentialManagerCLI compiled with TEST_COMMAND");
        System.out.println("... CredentialManagerCLI compiled with TEST_COMMAND");
end[TEST_COMMAND]*/  
        
        //############################ COMMAND INSTALL ########################
        
        if (this.validateCommands(this.commandProperties, line.getOptions(), Command.COMMAND_TYPE.INSTALL)) {
                
        	//final File appXml = new File(line.getOptionValue(this.commandProperties.getProperty("command.xml.shortname")));
        	        	
                File appXml = null;
                if (line.hasOption(this.commandProperties.getProperty("command.xml.shortname"))) {
                    appXml = new File(line.getOptionValue(this.commandProperties.getProperty("command.xml.shortname")));
                    LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_READ_APPFILE), appXml.toString());
                    
                } else if (line.hasOption(this.commandProperties.getProperty("command.path.shortname"))) {
                    appXml = new File(line.getOptionValue(this.commandProperties.getProperty("command.path.shortname")));
                    LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_READ_APPPATH), appXml.toString());
               }
                
            /**
             * force and reset are not more used
             */
            //final boolean forceOverWrite = false;
            //if (line.hasOption(this.commandProperties.getProperty("command.force.shortname"))) {
            //    forceOverWrite = true;   
            //}
            //final boolean forceReset = false;
            //if (line.hasOption(this.commandProperties.getProperty("command.reset.shortname"))) {
            //    forceReset = true;   
            //}
            
            command = new CommandInstall(appXml);

          //############################ COMMAND HELP ########################
        } else if (this.validateCommands(this.commandProperties, line.getOptions(), Command.COMMAND_TYPE.HELP)) {
            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS), Command.COMMAND_TYPE.HELP.toString());

            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_END_COMMANDS));

            command = new CommandHelp();

            //############################ COMMAND VERSION ########################
          } else if (this.validateCommands(this.commandProperties, line.getOptions(), Command.COMMAND_TYPE.VERSION)) {
              LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS), Command.COMMAND_TYPE.VERSION.toString());

              LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_END_COMMANDS));

              command = new CommandVersion();
              
          //############################ COMMAND CHECK ########################
          } else if (this.validateCommands(this.commandProperties, line.getOptions(), Command.COMMAND_TYPE.CHECK)) {
              LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS), Command.COMMAND_TYPE.CHECK.toString());
              LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_END_COMMANDS));

              File appXml = null;
              boolean firstDailyRun = false;
              
              if (line.hasOption(this.commandProperties.getProperty("command.dailyrun.shortname"))) {
                  firstDailyRun = true;
                  LOG.debug(Logger.getLogMessage(Logger.LOG_INFO_EXECUTE_FIRST_DAILY_RUN));
              }
              
              if (line.hasOption(this.commandProperties.getProperty("command.xml.shortname"))) {
                  appXml = new File(line.getOptionValue(this.commandProperties.getProperty("command.xml.shortname")));
                  LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_READ_APPFILE), appXml.toString());
              } else if (line.hasOption(this.commandProperties.getProperty("command.path.shortname"))) {
                  appXml = new File(line.getOptionValue(this.commandProperties.getProperty("command.path.shortname")));
                  LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_READ_APPPATH), appXml.toString());
              }
            command = new CommandCheck(appXml, firstDailyRun);
            
// MUNGE CONDITIONAL TAG
/*if[TEST_COMMAND]
          //############################ COMMAND TEST ########################
        } else if (this.validateCommands(this.commandProperties, line.getOptions(), Command.COMMAND_TYPE.TEST)) {
            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS), Command.COMMAND_TYPE.TEST.toString());
            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_VALIDATE_END_COMMANDS));
            
            final String arguments = line.getOptionValue(this.commandProperties.getProperty("command.test.shortname"));
            command = new CommandTest();
            ((CommandTest)command).setArguments(arguments);
end[TEST_COMMAND]*/    
            
        } else {
            final StringBuilder arguments = new StringBuilder();

            for (final String argumentLine : args) {
                arguments.append(argumentLine).append(" ");
            }

            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_VALIDATE_COMMANDS), arguments.toString());

            LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_VALIDATE_COMMANDS));

            throw new CredentialManagerException((Logger.getLogMessage(Logger.LOG_ERROR_COMMANDS_INVALIDE).replace(
                    "{}", new CommandHelp().getHelpMessage())));
        }

        return command;
    }

    @SuppressWarnings("static-access")
    private Options buildCommandsFlags(final Properties prop) {

        final Options optionsFlags = new Options();
        final Option install = OptionBuilder.withLongOpt(prop.getProperty("command.install.withLongOpt")).hasArgs(0)
                .hasArg(false).withDescription(prop.getProperty("command.install.withDescription"))
                .create(prop.getProperty("command.install.shortname"));

//        final Option force = OptionBuilder.withLongOpt(prop.getProperty("command.force.withLongOpt")).hasArgs(0)
//                .hasArg(false).withDescription(prop.getProperty("command.force.withDescription"))
//                .create(prop.getProperty("command.force.shortname"));

//        final Option reset = OptionBuilder.withLongOpt(prop.getProperty("command.reset.withLongOpt")).hasArgs(0)
//                .hasArg(false).withDescription(prop.getProperty("command.reset.withDescription"))
//                .create(prop.getProperty("command.reset.shortname"));
        
        final Option xml = OptionBuilder.withLongOpt(prop.getProperty("command.xml.withLongOpt"))
                .withDescription(prop.getProperty("command.xml.withDescription"))
                .withArgName(prop.getProperty("command.xml.withArgName")).hasArg(true)
                .hasArgs(Integer.parseInt(prop.getProperty("command.xml.hasArgs")))
                .create(prop.getProperty("command.xml.shortname"));

        final Option help = OptionBuilder.withLongOpt(prop.getProperty("command.help.withLongOpt"))
                .withDescription(prop.getProperty("command.help.withDescription"))
                .create(prop.getProperty("command.help.shortname"));

        final Option check = OptionBuilder.withLongOpt(prop.getProperty("command.check.withLongOpt"))
                .withDescription(prop.getProperty("command.check.withDescription"))
                .create(prop.getProperty("command.check.shortname"));

        final Option path = OptionBuilder.withLongOpt(prop.getProperty("command.path.withLongOpt"))
                .withDescription(prop.getProperty("command.path.withDescription"))
                .withArgName(prop.getProperty("command.path.withArgName")).hasArg(true)
                .hasArgs(Integer.parseInt(prop.getProperty("command.path.hasArgs")))
                .create(prop.getProperty("command.path.shortname"));
        
        final Option dailyrun = OptionBuilder.withLongOpt(prop.getProperty("command.dailyrun.withLongOpt"))
                .withDescription(prop.getProperty("command.dailyrun.withDescription"))
                .create(prop.getProperty("command.dailyrun.shortname"));
 
        final Option version = OptionBuilder.withLongOpt(prop.getProperty("command.version.withLongOpt"))
                .withDescription(prop.getProperty("command.version.withDescription"))
                .create(prop.getProperty("command.version.shortname"));
        
        final Option test = OptionBuilder.withLongOpt(prop.getProperty("command.test.withLongOpt"))
                .withDescription(prop.getProperty("command.test.withDescription"))
                .withArgName(prop.getProperty("command.test.withArgName")).hasArg(true)
                .hasArgs(Integer.parseInt(prop.getProperty("command.test.hasArgs")))
                .create(prop.getProperty("command.test.shortname"));
        
        optionsFlags.addOption(install);
//        optionsFlags.addOption(force);
//        optionsFlags.addOption(reset);
        optionsFlags.addOption(xml);
        optionsFlags.addOption(check);
        optionsFlags.addOption(path);
        optionsFlags.addOption(dailyrun);
        optionsFlags.addOption(help);
        optionsFlags.addOption(version);
        
        optionsFlags.addOption(test);

        return optionsFlags;
    }

    private boolean validateCommands(final Properties prop, final Option[] opts, final Command.COMMAND_TYPE commandType) {

        boolean control = true;
        String optionsStr = "";
        for (final String valideSequenceOfCommands : this.getValidArguments(prop, commandType)) {
            control = true;
            for (final Option opt : opts) {
                optionsStr += " -" + opt.getOpt();
                if (valideSequenceOfCommands.indexOf(opt.getOpt()) < 0) {
                    control = false;
                }

            }

            for (final String vsSequence : valideSequenceOfCommands.split(" ")) {
                if (optionsStr.indexOf(vsSequence) < 0) {
                    control = false;
                }

            }

            if (control) {

                return true;
            }

        }

        return control;
    }

    private CommandLine getCommandsParsed(final Options options, final String[] arguments) {

        final CommandLineParser parser = new GnuParser();
        final StringBuilder stringOptions = new StringBuilder();
        boolean valid = false;
        try {

            for (final String argumentOption : arguments) {
                stringOptions.append(argumentOption).append(" ");
                if (!valid && (argumentOption.startsWith("-") || argumentOption

                .startsWith("--"))) {

                    valid = true;
                }
            }
        } catch (final Exception ex) {

        }
        LOG.info(Logger.getLogMessage(Logger.LOG_INFO_PARSE_START_COMMANDS), stringOptions.toString());
        try {
            final CommandLine commandLine = parser.parse(options, arguments);

            if (!valid) {
                throw new org.apache.commons.cli.UnrecognizedOptionException("Unrecognized option: " + stringOptions);
            }

            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_PARSE_COMMANDS), stringOptions.toString());

            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_PARSE_END_COMMANDS), stringOptions.toString());
            return commandLine;
        } catch (final Exception e) {

            LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_PARSE_COMMANDS), stringOptions.toString());

            throw new CredentialManagerException(e);

        }

    }

    private List<String> getValidArguments(final Properties prop, final Command.COMMAND_TYPE type) {
        final List<String> list = new ArrayList<String>();
        String commandString = "install";
        if (type.equals(Command.COMMAND_TYPE.INSTALL)) {
            commandString = "install";
        } else if (type.equals(Command.COMMAND_TYPE.HELP)) {
            commandString = "help";
        } else if (type.equals(Command.COMMAND_TYPE.VERSION)) {
            commandString = "version";
        } else if (type.equals(Command.COMMAND_TYPE.CHECK)) {
            commandString = "check";
        } else if (type.equals(Command.COMMAND_TYPE.TEST)) {
            commandString = "test";
        }
        for (final String vArg : prop.getProperty("command." + commandString + ".valideArguments").split(",")) {
            list.add(vArg);
        }
        return list;

    }
}

