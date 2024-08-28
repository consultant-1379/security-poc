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

package com.ericsson.itpf.security.pki.cmdhandler.mapper;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.oss.services.scriptengine.spi.dtos.*;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadRequestDto;

@RunWith(MockitoJUnitRunner.class)
public class PkiToSEResponseMapperTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(PkiToSEResponseMapper.class);

    @InjectMocks
    PkiToSEResponseMapper pkiToSEResponseMapper;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
    }

    @Test
    public void testConvertToCommandResponseDtoWithSimpleMessage() {
        final ResponseDto responseDto = new ResponseDto(new ArrayList<AbstractDto>());
        pkiToSEResponseMapper.convertToCommandResponseDto(responseDto, PkiCommandResponse.message("Command Executed Successfully"));
        Assert.assertEquals("Command Executed Successfully", responseDto.getElements().get(0).toString());
    }

    @Test
    public void testConvertToCommandResponseDtoWithDownloadRequestType() {
        final ResponseDto responseDto = new ResponseDto(new ArrayList<AbstractDto>());
        final PkiDownloadRequestToScriptEngine downloadRequestToScriptEngine = new PkiDownloadRequestToScriptEngine();
        downloadRequestToScriptEngine.setFileIdentifier("_1234");
        pkiToSEResponseMapper.convertToCommandResponseDto(responseDto, downloadRequestToScriptEngine);
        Assert.assertEquals(((FileDownloadRequestDto) responseDto.getElements().get(1)).getFileId(), "_1234");
    }

    @Test
    public void testConvertToCommandResponseDtoWithPkiNameValueCommandResponse() {
        final ResponseDto responseDto = new ResponseDto(new ArrayList<AbstractDto>());
        final PkiNameValueCommandResponse commandResponse = new PkiNameValueCommandResponse();
        commandResponse.add("profileId", "profilename");
        commandResponse.add("1234", "certprofile1");
        pkiToSEResponseMapper.convertToCommandResponseDto(responseDto, commandResponse);
        Assert.assertEquals(responseDto.getElements().get(1).toString(), "[value:1234;width:9, value:certprofile1;width:12]");

    }

    @Test
    public void testConvertToCommandResponseDtoPkiNameMultipleValueCommandResponse() {
        final ResponseDto responseDto = new ResponseDto(new ArrayList<AbstractDto>());
        PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(1);
        String[] d = { "hi", "bye" };
        commandResponse.add("id", d);
        pkiToSEResponseMapper.convertToCommandResponseDto(responseDto, commandResponse);
        Assert.assertEquals(responseDto.getElements().get(2).toString(), "Command Executed Successfully");
    }

    @Test
    public void testConvertToCommandResponseDtoPkiNameMultipleValueCommandResponsewithzeroentry() {
        final ResponseDto responseDto = new ResponseDto(new ArrayList<AbstractDto>());
        PkiNameMultipleValueCommandResponse commandResponse = new PkiNameMultipleValueCommandResponse(0);
        pkiToSEResponseMapper.convertToCommandResponseDto(responseDto, commandResponse);
        Assert.assertEquals(responseDto.getElements().get(0).toString(), PkiToSEResponseMapper.EMPTY_RESULT_LIST_MESSAGE);
    }

    @Test
    public void nameValueResponseTestMultipleEntries() {
        final String name1 = "certificate Name", value1 = "certificate status";
        final String name2 = "name1", value2 = "enable";
        final String name3 = "name2", value3 = "disable";

        ResponseDto responseDto = new ResponseDto(new ArrayList<AbstractDto>());

        pkiToSEResponseMapper.convertToCommandResponseDto(responseDto, PkiCommandResponse.nameValue().add(name1, value1).add(name2, value2).add(name3, value3));

        List<String> rowsAsListOfStrings = getRowsAsListOfConcatenatedStrings(responseDto.getElements());

        assertTrue(rowsAsListOfStrings.get(2).contains("name1"));
        assertTrue(rowsAsListOfStrings.get(2).contains(value2));
        assertTrue(rowsAsListOfStrings.get(1).contains("name2"));
        assertTrue(rowsAsListOfStrings.get(1).contains(value3));
    }

    private List<String> getRowsAsListOfConcatenatedStrings(List<AbstractDto> elements) {
        List<String> rowsAsConcatenatedStrings = new ArrayList<>();

        for (AbstractDto dto : elements) {

            if (dto instanceof RowDto) {
                RowDto rowDto = (RowDto) dto;
                StringBuilder row = new StringBuilder();
                for (RowCell cell : rowDto.getElements()) {
                    row.append(cell.getValue() + " ");
                }
                rowsAsConcatenatedStrings.add(row.toString());
            } else {
                LineDto lineDto = (LineDto) dto;
                rowsAsConcatenatedStrings.add(lineDto.getValue());
            }

        }
        return rowsAsConcatenatedStrings;
    }
}
