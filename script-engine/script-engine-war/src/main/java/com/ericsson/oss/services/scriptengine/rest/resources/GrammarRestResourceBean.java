package com.ericsson.oss.services.scriptengine.rest.resources;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FilenameFilter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.ws.rs.core.Response;

import org.slf4j.Logger;

public class GrammarRestResourceBean implements GrammarRestResource {

    private static final String GRAMMAR_FILE_LOCATION = File.separator+"ericsson"+File.separator+"config_mgt"+File.separator+"ebnfToJson" +File.separator;
    private static final String GRAMMAR_FILE_FORMAT = ".json";

    @Inject
    private Logger logger;

    @Override
    public Response getDeployedApplicationsNameAsJSON(){

        logger.debug("Received a request to fetch deployed applications applications grammar: ");
        Response response=null;

        final String availableCommandsetsInGrammar = getCommandsetNamesInGrammarLocation(GRAMMAR_FILE_LOCATION);
        if (availableCommandsetsInGrammar==null) {
            response = Response.serverError().build();
        }else {
            response = Response.status(Response.Status.OK).entity(availableCommandsetsInGrammar).build();
        }
        return response;
    }

    public String getCommandsetNamesInGrammarLocation(final String fileLocation){

        String[] applicationsCommandSetList = null;
        File grammarJSONfileDirectory = null;
        final ArrayList applicationCommandSetName = new ArrayList<String>();
        try{
            grammarJSONfileDirectory = new File(fileLocation);
            final FilenameFilter jsonFilter = getJsonFilter();
            applicationsCommandSetList = grammarJSONfileDirectory.list(jsonFilter);
            if(applicationsCommandSetList==null){
                throw new FileNotFoundException();
            }

            for (final String applicationCommandSetFileName : applicationsCommandSetList){
                applicationCommandSetName.add('"'+getBaseName(applicationCommandSetFileName)+'"');
            };

        }catch(final Exception e){
            logger.error("getCommandsetNamesInGrammarLocation Exception message = {}",e.getMessage());
        }
        final String deployedApplicationsCommandsets = "{ \"commandSetsDeployed\" : " + applicationCommandSetName + "}" ;
        return deployedApplicationsCommandsets;
    }

    @Override
    public Response readJSONForApplication(final String applicationName ) throws IOException {

        Response response = null;
        final String grammarfileName =  GRAMMAR_FILE_LOCATION + applicationName + GRAMMAR_FILE_FORMAT;
        final String grammar=getCommandsetGrammar(grammarfileName);
        logger.debug(" File name of grammar is "+ grammarfileName);

        if(grammar==null || grammar == ""){
            response = Response.serverError().build();
            logger.debug("Received a request to fetch grammar for command set of application : " + applicationName);
        } else {
            response = Response.status(Response.Status.OK).entity(grammar).build();
        }
        return response;
    }

    public String getCommandsetGrammar(final String fileNameWithPath) throws IOException {

        String commandsetGrammar = "";
        try {
            final  List<String> lines = Files.readAllLines(Paths.get(fileNameWithPath), Charset.defaultCharset());
            for(final String line : lines){
                logger.debug(" File content is " + line);
                commandsetGrammar = commandsetGrammar + line;
            }
        } catch (final IOException e) {
            logger.error("getCommandsetGrammar Exception message = {}",e.getMessage());
        }
        return commandsetGrammar;
    }

    /*
     * P R I V A T E - M E T H O D S
     */
    private String getBaseName(String applicationCommandSetFileName) {
        final int pos = applicationCommandSetFileName.lastIndexOf(".");
        if (pos>0){
            applicationCommandSetFileName = applicationCommandSetFileName.substring(0,pos);
        }
        return applicationCommandSetFileName;
    };

    private FilenameFilter getJsonFilter() {
        final FilenameFilter jsonFilter = new FilenameFilter() {
            @Override
            public boolean accept(final File dir, final String name) {
                if (name.toLowerCase().endsWith(GRAMMAR_FILE_FORMAT)){
                    return true;
                } else {
                    return false;
                }
            }
        };

        return jsonFilter;
    }
}
