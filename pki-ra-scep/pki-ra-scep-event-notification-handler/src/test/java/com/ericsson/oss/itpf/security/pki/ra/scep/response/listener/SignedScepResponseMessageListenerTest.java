/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.scep.response.listener;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.PkiScepServiceException;
import com.ericsson.oss.itpf.security.pki.ra.scep.response.processor.ResponseProcessor;
import com.ericsson.oss.itpf.security.pkira.scep.event.SignedScepResponseMessage;

/**
 * This class contains tests for ResponseMessageListener
 */
@RunWith(MockitoJUnitRunner.class)
public class SignedScepResponseMessageListenerTest {

    @InjectMocks
    private SignedScepResponseMessageListener responseMessageListener;
    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    ResponseProcessor responseProcessor;

    private SignedScepResponseMessage scepResponseMessage;
    private String scepResponse = null;

    @Before
    public void setUp() {
        scepResponse = "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c2NlcFJlc3BvbnNlRGF0YT48Y2VydGlmaWNhdGU+TUlJRTF6Q0NBcitnQXdJQkFnSUlmV3NkallTalNnRXdEUVlKS29aSWh2Y05BUUVMQlFBd0V6RVJNQThHQTFVRUF3d0lRVkpLWDFKdmIzUXdIaGNOTVRVeE1ERXlNRFUxT0RVNVdoY05NVGN4TURFeU1EVTFPRFU1V2pBMk1STXdFUVlEVlFRRERBcEJVa3BmVTFWQ1gwTkJNUkl3RUFZRFZRUXVFd2xFVGw5VFZVSmZRMEV4Q3pBSkJnTlZCQVlUQWtsT01JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBbWNFQUprNXo0TTcyUnJ6djJ4ZG1LLytFajE5NW94aDM1VlFNVE1LQTZOa1ljdGUwSXNSTDM1blh3QUZEMlNyTEFWdHA5V2pUZmUrc3lJQ3NudnMrMkh5SDRLTXJieHZRbXFDUjByLzRkYW1CcVBkWkptVFZaSmppejg4WTVnTmpiQ09SNnlMVHEwR012eFROWkZvamJGQVk2bGVSMmllY2lYOFNybENRODdURm1EMEsvR05CMTZ3bTdzTnVjRjkzWU9BZHNRTU5DbWZSUDZMdmswc1RBK3NsNmR1QUEyUHhhb1NOaGxocnNLQlJYSzBCZWQ5RGZkV3JyWVVCTG10Mm5oak9hWGxVckdpMnEyWnR6Und6UXp2RENUbVFUZy8xTWpJTXZlZGs3VFMrL3ZzeFptcWJaNy9FMDRLdGQ4ZDRwVGJNTzJZYktFU1lnYUovRGx1K2x3SURBUUFCZ1FJSGdJSUNCNENqZ2dFQ01JSC9NQXdHQTFVZEV3RUIvd1FDTUFBd0h3WURWUjBqQkJnd0ZvQVVZQ0FwOElLVXFPZFRrUzJsQm5kZGFiM2FsakV3SFFZRFZSME9CQllFRk1kbU4rcG54alMvQzVCWGJwUWM0bXA4cGIwS01HVUdBMVVkSHdSZU1Gd3dXcUJVb0ZLR1VHeGtZWEE2THk5c1pHRndMbVY0WVcxd2JHVXVZMjl0TDJOdVBXVjRZVzF3YkdWRFFTeGtZejFsZUdGdGNHeGxMR1JqUFdOdmJUOWpaWEowYVdacFkyRjBaVkpsZG05allYUnBiMjVNYVhOMGdRSUdRREFqQmdOVkhSRUVIREFhcEJnd0ZqRVVNQklHQTFVRUxoTUxkM2QzTG5oNWVpNWpiMjB3RGdZRFZSMFBBUUgvQkFRREFnRUdNQk1HQTFVZEpRUU1NQW9HQ0NzR0FRVUZCd01JTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFCcHZoYnBWdEZiRVN5S0d3bGdPR3NrdHVVWWpaaXAvdzBNYTd1dDdyeEFOMTVZbmcrYWNwOWx4WTVtcXVKKzhXUWljN0Z0di95SFRyTGZ3bkVkUmN4dlBrUGxwb096RmFXTmNIbS9wWmVVREY0bkh1S29ZOG4xaVpqT21ENkp0Q1psT3pnNjV6ejhGb1V6Z09EOFFHWWFlQTNpWG5pVkU4TWNOWGg5Z094a1NlaTZWc1ZkWldFUXFtVGFxQW5iQVQ3UzlOVnRDNnVaSTZncldJVVVxUkx1WGcza3BIVXJrcVFtY3EyUjBsNDJscGNTaXFNWDBZZnpINWI5cnA2Z1FsdkQ1dG1IQUhveGQyVWJHT1Bzc25NY3R3MlhaQk9WNkxUOFZZekIxczRHYmNIcnhzMFJPeXdIeUs0QzdiaTBhL00wOGtjZFo1SzFnV3VOanNvV1YwbVNXck04bmc3VGFnZmFFWDRQLzBESmttcGU4dWRRU2xuQi9FcHpmN2J6Sng3ckliMHJ1Ri92NkRET3NOV0U2aHNwamJZelhHQ2c0ajlRTEdxL3VjdzZuY2JwT0I5dFpCU0VxRkVMQURrQWVrb3o3SFR3MXRJY01Qc2dIM21iTlllcjVtdEZXK3R5eVVoa2RQWGpjNllyQVNicDdPMTkrWGdCL0JSMG1UcHc2RFNNKzdRS3VoY1BGNU9odVdMUE5tNUhIN2o1eTRtQnJhVFBHUFFUNjFKcXhXTVhSaTdaanBVckdrMmxFQTRPNnVzM0dBSVBsM3UzR0t1a3pHbG5HNTlxd0l1SVMramdLaFRPWTFCOHMrWStZeVVpZkh5RUw1SGJuc3h3YU5vQnZ2UkI2d05pZVN1aG8xRWVPQnVRRVlZRlZ2b0FzaWZJaUFPaFh1V0llVC9ubFE9PTwvY2VydGlmaWNhdGU+PHN0YXR1cz4wPC9zdGF0dXM+PHRyYW5zYWN0aW9uSWQ+MTI8L3RyYW5zYWN0aW9uSWQ+PFNpZ25hdHVyZSB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnIyI+PFNpZ25lZEluZm8+PENhbm9uaWNhbGl6YXRpb25NZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy9UUi8yMDAxL1JFQy14bWwtYzE0bi0yMDAxMDMxNSIvPjxTaWduYXR1cmVNZXRob2QgQWxnb3JpdGhtPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwLzA5L3htbGRzaWcjcnNhLXNoYTEiLz48UmVmZXJlbmNlIFVSST0iIj48VHJhbnNmb3Jtcz48VHJhbnNmb3JtIEFsZ29yaXRobT0iaHR0cDovL3d3dy53My5vcmcvMjAwMC8wOS94bWxkc2lnI2VudmVsb3BlZC1zaWduYXR1cmUiLz48L1RyYW5zZm9ybXM+PERpZ2VzdE1ldGhvZCBBbGdvcml0aG09Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvMDQveG1sZW5jI3NoYTI1NiIvPjxEaWdlc3RWYWx1ZT5yMDljOUVqeGxKNFhkbW4yWlljR2lXdHl0WE9oZnVuc1M0MkI0VW5xMHlRPTwvRGlnZXN0VmFsdWU+PC9SZWZlcmVuY2U+PC9TaWduZWRJbmZvPjxTaWduYXR1cmVWYWx1ZT5paG5jcktlVU9jWVord1I5cWZWSXR6TlNMaTdYd2phNkk4bU1ySm9aNW9leTRqZ1NNbmViQzRiaTl4WWUzc2JIcjlkc0dZRlhCNU5HVVB5cmp3RXNGc2p6MmwrcElJeWFleDZtSlZLU0VDekpaZDdtVXJqYWVFNmZMZ3VOVTRXcGQxTk9ibXhwa01rTk5naWh0bzI0M0JUSStZZlVoemJGN3p2WUpzTFYyOXRGbVllK251Q05qcmQ4ejBNWXZhbVJaN3MraG1KeGJGa21xSUxMY29DM1B2ak1ncDdERDREOGtWUTVYcXQzL3pKSTdVTDNPS0RjZDZkZy84cit4eVZSVTRKTitiVWxueHZEWmV4TjB2UGlGT0syeEdBbzM4L05CQ1IvSCsyMGk2UGkvdm1VNENudVpONU1FK3o1eC9XVW1DNHNpdHJGSytVZUtEVFYwY09BV1E9PTwvU2lnbmF0dXJlVmFsdWU+PEtleUluZm8+PFg1MDlEYXRhPjxYNTA5Q2VydGlmaWNhdGU+TUlJRCtUQ0NBdUdnQXdJQkFnSUVKRzIxRURBTkJna3Foa2lHOXcwQkFRVUZBREF4TVJFd0R3WURWUVFLREFoRmNtbGpjM052YmpFY01Cb0dBMVVFQXd3VFRGUkZTVkJUWldOT1JXTjFjMUp2YjNSRFFUQWVGdzB4TkRFeE1EVXdOakk1TWpkYUZ3MHhPVEV4TURNeE1qSTVNakZhTUM0eExEQXFCZ05WQkFNTUkweFVSVWxRVTJWalRrVmpkWE5oZEdOc2RtMHhNREkwVTJObGNGSmhVMlZ5ZG1WeU1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcHV1QUdabXZzVjladmxYeW15QzZPVC9nL3h5L25MVURPTE5nOCs1YVB6NlZTL0d5SE9hbGJXK2hyeHdSUWYyUlNETlByaFoxTHF2bWh0MUpPR1Z5QUVHR0E0cktXODV3YUFxbCs2a0U4STZYRjUvWGJ4Szl4M3Q3MWJ6cFdWRlVvQk1hNkMxQTRMYk9ETDZucEw2OFJpdVFCK3I4SzJlcDNIV1M2bjZlZVc2UTJZdVU0bUsvRFFpeFVzdGp0bXBJWkdRbWVqZkdIb0hrS2E5dkRqeEpYeXp0RTlkUHZSZUZMVFV2TXFvckpwc0RHVzNPREUvRWFNY0FrRjBneVIvcmRFUFNUWUtEd1NwR1d3bTl4MVcxUkROSmdrY3Y4d3o2Q1h4YXdpSG9haVpiQVVHZ01nbU9lTlhGTDU2VDBuenN2YjZvNlk5TDR6OWQwdmdjSlJPbzB3SURBUUFCbzRJQkdqQ0NBUll3SFFZRFZSME9CQllFRlBpU0wvM2VZOTVyUGFBSTZPWW9NWTlBdEZhZU1Bd0dBMVVkRXdFQi93UUNNQUF3SHdZRFZSMGpCQmd3Rm9BVWt1ZU9KUEl3M1M4L2RZZmllV2NzaEVXS0R6Z3dnYlVHQTFVZEh3U0JyVENCcWpCVG9GR2dUNFpOYUhSMGNEb3ZMMk5rY0RFdVkyUndjeTVoZEdoMFpXMHVaV1ZwTG1WeWFXTnpjMjl1TG5ObE9qSXpOemN2YVc1MFpYSnVZV3d2VEZSRlNWQlRaV05PUldOMWMxSnZiM1JEUVM1amNtd3dVNkJSb0UrR1RXaDBkSEE2THk5alpIQXlMbU5rY0hNdVlYUm9kR1Z0TG1WbGFTNWxjbWxqYzNOdmJpNXpaVG95TXpjM0wybHVkR1Z5Ym1Gc0wweFVSVWxRVTJWalRrVmpkWE5TYjI5MFEwRXVZM0pzTUE0R0ExVWREd0VCL3dRRUF3SURxREFOQmdrcWhraUc5dzBCQVFVRkFBT0NBUUVBTzQwYzVCVEpaTDlmUVhxZ2JqV0dmTjlLYWtWK1QrV2phb2NyVUc2Y0swNFpIdGozeDFja3RkSS83N0xtc0k5eHB1T0tRZlZtTWUwSmdoWTlxQmxTbzBXMk02TFV5cHNEYXBBQVlTRmZoODhkdHdHT0drbGtTb0dLREJPRDNkcXVNMDIvdnFqZmZhN0MzWXUvekJINTJwekcraDhTeUVSZ21Wb3RLNnBPbC95UjZxeEYycUJ4dWsraTNoU3NqQlV1QTFSS2NlaFFRbnUxQWcwUmNwR3puQUg0Qm84MnBYOFltUHc0WFh3VmlzcHQ3TG5MNmZWM0o5MnRHRDRJelJzbjlKRUNYRWpGR21GUmtzYkI4RXdFY3FFWEpJQ0hPYzJjUDFSS05Wd3BRWkN0TFpVY0xGOU1YTkNFSk9qNFBscDYvSUg0dmF0eGRWWXBNR28rQkY2QmdRPT08L1g1MDlDZXJ0aWZpY2F0ZT48L1g1MDlEYXRhPjwvS2V5SW5mbz48L1NpZ25hdHVyZT48L3NjZXBSZXNwb25zZURhdGE+";
        scepResponseMessage = new SignedScepResponseMessage();
        scepResponseMessage.setScepResponse(scepResponse.getBytes());
    }

    /**
     * This method tests receiving ScepResponseMessage over ScepResponseChannel
     */
    @Test
    public void receiveScepMessageTest() {
        try {
            responseMessageListener.receiveResponseMessage(scepResponseMessage);
            Mockito.verify(logger).info("SignedScepResponseMessage received over the ScepResponseChannel");
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void receiveScepMessageElseTest() {
        try {
            responseMessageListener.receiveResponseMessage(scepResponseMessage);
            Mockito.verify(logger).info("SignedScepResponseMessage received over the ScepResponseChannel");
        } catch (Exception e) {
            Assert.fail(e.getMessage());
        }
    }

    @Test(expected = Exception.class)
    public void receiveScepMessageTestException() {
        Mockito.doThrow(new PkiScepServiceException("Exception occurred")).when(responseProcessor).processResponse(scepResponseMessage);
        responseMessageListener.receiveResponseMessage(scepResponseMessage);

    }
}
