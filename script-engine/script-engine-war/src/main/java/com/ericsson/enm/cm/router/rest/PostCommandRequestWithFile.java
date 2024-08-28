package com.ericsson.enm.cm.router.rest;

import java.io.InputStream;

import javax.ws.rs.FormParam;

public class PostCommandRequestWithFile {

    private String command;

    private InputStream file;

    private String fileName;

    public String getCommand() {
        return command;
    }

    public InputStream getFile() {
        return file;
    }

    public String getFileName() {
        return fileName;
    }

    public boolean hasFile() {
        return getFile() != null;
    }

    @FormParam("command")
    public void setCommand(final String command) {
        this.command = command;
    }

    @FormParam("file:")
    public void setFile(final InputStream file) {
        this.file = file;
    }

    @FormParam("fileName")
    public void setFileName(final String fileName) {
        this.fileName = fileName;
    }
}
