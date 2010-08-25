package org.waffle.pam;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.MessagePolicy;
import javax.security.auth.message.module.ServerAuthModule;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

/**
 *
 * @author mikael
 */
public abstract class AbstractHTTPServerAuthModule implements ServerAuthModule {
    public static final String AUTH_TYPE_INFO_KEY = "javax.servlet.http.authType";
    
    protected static Map<HttpSession, GroupPrincipal> principals =
            Collections.synchronizedMap(new WeakHashMap<HttpSession, GroupPrincipal>());
    
    protected static Class[] supportedMessageTypes =
            new Class[]{HttpServletRequest.class, HttpServletResponse.class};

    protected CallbackHandler handler;
    protected Map             options;
    protected String          policyContextID;
    protected MessagePolicy   requestPolicy;
    protected MessagePolicy   responsePolicy;

    /**
     * Remove method specific principals and credentials from the server.
     *
     * @param messageInfo a contextual object that encapsulates the
     * client request and server response objects, and that may be
     * used to save state across a sequence of calls made to the
     * methods of this interface for the purpose of completing a
     * secure message exchange.
     * @param server     the Subject instance from which the Principals and
     * credentials are to be removed.
     * throws AuthException If an error occurs during the Subject
     * processing.
     */
    public void cleanSubject(MessageInfo messageInfo, Subject subject) throws AuthException {
        if (subject != null) {
            subject.getPrincipals().clear();
        }
    }

    /**
     * Get the one or more Class objects representing the message types
     * supported by the module.
     *
     * @return An array of Class objects, with at least one element
     * defining a message type supported by the module.
     */
    public Class[] getSupportedMessageTypes() {
        return supportedMessageTypes;
    }


    public void initialize(MessagePolicy requestPolicy, MessagePolicy responsePolicy, CallbackHandler handler, Map options) throws AuthException {
        this.requestPolicy = requestPolicy;
        this.responsePolicy = responsePolicy;
        this.handler = handler;
        this.options = options != null ? options : new HashMap();
    }



    /**
     * Secure a service response before sending it to the client.
     * <p/>
     * This method is called to transform the response message acquired by
     * calling getResponseMessage (on messageInfo) into the mechanism-specific
     * form to be sent by the runtime.
     * <p> This method conveys the outcome of its message processing either
     * by returning an AuthStatus value or by throwing an AuthException.
     *
     * @param messageInfo    A contextual object that encapsulates the
     * client request and server response objects, and that may be
     * used to save state across a sequence of calls made to the
     * methods of this interface for the purpose of completing a
     * secure message exchange.
     * @param server A Subject that represents the source of the
     * service
     * response, or null. It may be used by the method implementation
     * to retrieve Principals and credentials necessary to secure
     * the response. If the Subject is not null,
     * the method implementation may add additional Principals or
     * credentials (pertaining to the source of the service
     * response) to the Subject.
     * @return An AuthStatus object representing the completion status of
     * the processing performed by the method.
     * The AuthStatus values that may be returned by this method
     * are defined as follows:
     * <p/>
     * <ul>
     * <li> AuthStatus.SEND_SUCCESS when the application response
     * message was successfully secured. The secured response message may be
     * obtained by calling getResponseMessage on messageInfo.
     * <p/>
     * <li> AuthStatus.SEND_CONTINUE to indicate that the application response
     * message (within messageInfo) was replaced with a security message
     * that should elicit a security-specific response (in the form of a
     * request) from the peer.
     * <p/>
     * This status value serves to inform the calling runtime that
     * (to successfully complete the message exchange) it will
     * need to be capable of continuing the message dialog by processing
     * at least one additional request/response exchange (after having
     * sent the response message returned in messageInfo).
     * <p/>
     * When this status value is returned, the application response must
     * be saved by the authentication module such that it can be recovered
     * when the module's validateRequest message is called to process
     * the elicited response.
     * <p/>
     * <li> AuthStatus.SEND_FAILURE to indicate that a failure occurred while
     * securing the response message and that an appropriate failure response
     * message is available by calling getResponseMeessage on messageInfo.
     * </ul>
     * throws AuthException When the message processing failed without
     * establishing a failure response message (in messageInfo).
     */
    public AuthStatus secureResponse(MessageInfo messageInfo, Subject serviceSubject) throws AuthException {
        System.out.println("AbstractHTTPServerAuthModule: " + messageInfo + " serviceSubject: " + serviceSubject);
        return AuthStatus.SEND_SUCCESS;
    }

}
