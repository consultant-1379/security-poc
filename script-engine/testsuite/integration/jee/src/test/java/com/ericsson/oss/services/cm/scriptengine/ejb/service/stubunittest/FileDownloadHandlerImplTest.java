package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubunittest;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doThrow;

import java.io.IOException;

import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs.FileDownloadHandlerImpl;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileSystemLocatedFileDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.InMemoryFileDto;

public class FileDownloadHandlerImplTest {

    FileDownloadHandlerImpl objUnderTest = new FileDownloadHandlerImpl();
    ContextServiceStubForUnitTest contextServiceStubForUnitTest = new ContextServiceStubForUnitTest();

    @Before
    public void setupStubs() {
        objUnderTest.setContextServiceStub(contextServiceStubForUnitTest);
    }

    @Test
    public void execute_withSomeFileId_returnsFileSystemLocatedFileDtowithCorrectFile() {
        final FileDownloadResponseDto result = objUnderTest.execute("some fileId");
        assertFileNameAndMimeType(result);
        assertTrue(result instanceof FileSystemLocatedFileDto);
        final FileSystemLocatedFileDto fileSystemLocatedFileDto = (FileSystemLocatedFileDto) result;
        assertTrue(fileSystemLocatedFileDto.getFilePath().endsWith(result.getFileName()));
    }

    @Test
    public void execute_withInMemorySomeFileId_returnsInMemoryFileDtowithCorrectFileAndContent() {
        final FileDownloadResponseDto result = objUnderTest.execute("inMemory");
        assertFileNameAndMimeType(result);
        assertTrue(result instanceof InMemoryFileDto);
        final InMemoryFileDto inMemoryFileDto = (InMemoryFileDto) result;
        assertEquals(FileDownloadHandlerImpl.FILE_CONTENTS, new String(inMemoryFileDto.getFileContents()));
    }

    @Test(expected = RuntimeException.class)
    public void execute_withInvalidUserId_throwsRuntimeException() {
        contextServiceStubForUnitTest.userId = "invalid user id";
        objUnderTest.execute("");
    }

    @Test
    public void execute_withIOExceptionDuringFileCreationReturnsNull() throws IOException {
        final FileDownloadHandlerImpl objUnderTestWithSpy = Mockito.spy(objUnderTest);
        doThrow(new IOException()).when(objUnderTestWithSpy).createTempFile();
        assertNull(objUnderTestWithSpy.execute("some fileId"));
    }

    /*
     * P R I V A T E - M E T H O D S
     */

    private void assertFileNameAndMimeType(final FileDownloadResponseDto fileDownloadResponseDto) {
        assertTrue(fileDownloadResponseDto.getFileName().startsWith(FileDownloadHandlerImpl.FILE_NAME));
        assertTrue(fileDownloadResponseDto.getFileName().endsWith(FileDownloadHandlerImpl.FILE_EXT));
        assertEquals("text/plain", fileDownloadResponseDto.getMimeType());
    }

}
