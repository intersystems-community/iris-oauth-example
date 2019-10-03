Class OAuthClient.REST Extends %CSP.REST
{

Parameter OAUTH2APPNAME = "OAuthClient";

Parameter OAUTH2CLIENTREDIRECTURI = "https://52773b-76230063.labs.learning.intersystems.com/oauthclient/";

// to keep sessionId
Parameter UseSession As Integer = 1;

XData UrlMap [ XMLNamespace = "http://www.intersystems.com/urlmap" ]
{
    <Routes>
    	<Route Method="GET" Url = "/" Call = "Do" />
    </Routes>
}

ClassMethod Do() As %Status
{
    // Check for accessToken
    set isAuthorized = ##class(%SYS.OAuth2.AccessToken).IsAuthorized(
    	..#OAUTH2APPNAME,
    	.sessionId,
    	"scope1",
    	.accessToken,
    	.idtoken,
    	.responseProperties,
    	.error)
 
    // to show accessToken
    if isAuthorized {
   	 set valid = ##class(%SYS.OAuth2.Validation).ValidateJWT(
   		 ..#OAUTH2APPNAME,
   		 accessToken,
   		 "scope1",
   		 .aud,
   		 .JWTJsonObject,
   		 .securityParameters,
   		 .sc
   	 )
   	 &html< Hello!<br> >
   		 w "You access token = ", JWTJsonObject.%ToJSON()
   	 &html< </html> >
   	 quit $$$OK
    }

    // perform the process of user and client identification and get accessToken       
    set url = ##class(%SYS.OAuth2.Authorization).GetAuthorizationCodeEndpoint(
    	..#OAUTH2APPNAME,
    	"scope1",
    	..#OAUTH2CLIENTREDIRECTURI,
    	.properties,
    	.isAuthorized,
    	.sc)
 
    if $$$ISERR(sc) {
     	 w "error handling here"
     	 quit $$$OK
    }
    
    // url magic correction: change slashes in the query parameter to its code
    set urlBase = $PIECE(url, "?")
    set urlQuery = $PIECE(url, "?", 2)
    set urlQuery = $REPLACE(urlQuery, "/", "%2F")
    set url = urlBase _ "?" _ urlQuery
    
	&html<
   	 <html>
   		 <h1>Authorization in IRIS via OAuth2</h1>    
   		 <a href = "#(url)#">Authorization in <b>IRIS</b></a>
   	 </html>
	>
      
    quit $$$OK
}

} 
