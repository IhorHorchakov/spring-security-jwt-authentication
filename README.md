Demo project to set up JWT authentication using Spring Security

-------
_Authentication_ is the process of determining if the person accessing a system really is who they claim to be. 
Authentication systems allow or deny access based on credentials or other proof provided by those requesting access. 
Authentication typically works together with authorization, which determine what level of access a user should have.

Most common authentication methods: 
- username & password - a user enters their username and password into a login form, and if the credentials match what 
is stored in the database, the user is granted access. This method can be insecure if passwords are not properly 
encrypted or if users reuse the same password for multiple accounts;

- two-factor authentication - 2FA is when apart from entering the username & password correctly, you will be prompted 
for the second piece of information (usually a code generated by an app on your phone or a code sent via SMS);

- biometrics(face-id, touch-id, fingerprint) - identifies individuals based on their unique biological characteristics;

- passwordless login - a method of logging into an account without needing a username or a password. Users don't have to
remember yet another username and password combination, plus it's more secure. There are no weak passwords to be guessed
or brute-forced by attackers. Implies login + email(access by link on mailbox), or login + app on user's phone (need to 
enter one-time generated code);

- multi-factor (MFA) - this means that in addition to having a username and password, you will be required to provide 
extra proof depending on the system you are trying to access. This extra proof can range from a fingerprint to a secret 
security key or even a code generated randomly;

- token-based - a method of authenticating users that involves providing them with a unique token. This token can be 
used to identify the user and provide access to certain resources. Tokens can be used at different stages of the 
authentication process, including MFA and through protocols working on the backend between applications, APIs or websites.

There are a lot of tools we can use for token-based authentication: 
- Open Authorization (OAuth) emerged from the social web,
- Security Assertion Markup Language (SAML) is the backbone of web-based single sign-on (SSO), 
- OpenID Connect (OIDC) is ideal for connections between modern applications and applications that use RESTful APIs, 
- Client Initiated Backchannel Authentication (CIBA) is an extension to the OpenID Connect flow,
- JSON Web Token (JWT) is an open standard that contains encoded JSON objects, including a set of claims that cannot be 
altered after a token is issued. JWT is often used for web APIs, including RESTful APIs, to authenticate a user wanting 
access to the API.

-------
#### JWT Authentication

JWT authentication implies using JSON tokens to login on the web in general, not only for REST services.
It is robust and can carry a lot of information, but is still simple to use even though its size is relatively small. 
Like any other token, JWT can be used to pass the identity of authenticated users between an identity provider and a
ServiceProvider (which are not necessarily the same systems). 
It can also carry all the user’s claim, such as username, roles & permissions, so the service provider does not need to go
into the database or external systems to verify that authentication data for each request - that data is extracted from the token.

![client-server-flow](https://github.com/IhorHorchakov/spring-security-jwt-authentication/blob/master/img/jwt-client-server-flow.png?raw=true)

1) Client logs in by sending their credentials to the identity provider.
2) The identity provider verifies the credentials; if all is OK, it retrieves the user data, generates a JWT containing 
user details and permissions that will be used to access the services, and it also sets the expiration on the JWT 
(which might be unlimited). Identity provider signs, and if needed, encrypts the JWT and sends it to the client as a 
response to the initial request with credentials.
3) Client stores the JWT for a limited or unlimited amount of time, depending on the expiration set by the identity provider.
4) Client sends the stored JWT in an Authorization header for every request to the service provider.
5) For each request, the service provider takes the JWT from the `Authorization` header and decrypts it, 
validates the signature, and if everything is OK, extracts the user data and permissions. Based on this data solely, 
and again without looking up further details in the database or contacting the identity provider, it can accept or deny 
the client request. The only requirement is that the identity and service providers have an agreement on encryption so 
that service can verify the signature or even decrypt which identity was encrypted.

This flow allows for great flexibility while still keeping things secure and easy to develop. By using this approach, 
it is easy to add new server nodes to the service provider cluster, initializing them with only the ability to 
verify the signature and decrypt the tokens by providing them a shared secret key. No session replication, 
database synchronization or inter-node communication is required. REST in its full glory.

The main difference between JWT and other arbitrary tokens is the standardization of the token’s content. Another 
recommended approach is to send the JWT token in the `Authorization` header using the Bearer scheme. The content of the 
header should look like this:

`Authorization: Bearer <token>`

-------
Benefits of using tokens: 
- stateless (self-contained) - makes easy horizontal scaling; 
- provides fine-grained access control;
- flexible - expiration time (session or longer), exchangeable and refreshable;
- inherently more secured - because tokens don’t have to contain a user’s personal data and are algorithm/software generated,
they keep this data safer from hackers;
- cross-platform compatible;

Cons of using tokens: 
- compromised secret key – a major drawback of the token-based auth is that it relies on one key.
If the key is not managed properly by developers or website administrators and is compromised by attackers,
this can put sensitive information at risk;
- unsuitable for long-term authentication – systems that allow users to remain logged in for prolonged periods are less 
ideal. These tokens require frequent revalidation and can annoy users. Using refresh tokens and storing them correctly 
is a good workaround. Refresh tokens allow users to remain authenticated for longer periods without re-authorization;

-------
#### JWT authentication: Implementation using Spring Security setup


Spring Framework uses the approach of _configurers_ - an ability extend Spring configuration by adding custom components.

Spring Security has many _configurers_ to support important authentication features (see inheritors of AbstractHttpConfigurer):
- FormLoginConfigurer to enable authentication using username & password form submission,
- SessionManagementConfigurer to enable authentication by sessionId,
- RememberMeConfigurer typically involves the user checking a box when they enter their username and password that states to "Remember Me",
- LogoutConfigurer adds logout support,
- OAuth2ResourceServerConfigurer to enable authentication by using JWT.

Here is a high-level diagram of the JWT authentication flow:
![spring-security-authentication-flow](https://github.com/IhorHorchakov/spring-security-jwt-authentication/blob/master/img/spring-security-authentication-flow.png?raw=true)

The entry point of authentication process is BearerTokenAuthenticationFilter. Spring security filter chain intercepts and verifies every http request by using BearerTokenAuthenticationFilter.
This filter gets a JWT from request headers and passes it to AuthenticationManager. The AuthenticationManager leverages 
AuthenticationProvider to check a JWT using PasswordEncoder & UserDetailsService.

We use `OAuth2ResourceServerConfigurer` that plugs BearerTokenAuthenticationFilter in security filter chain.
![filter-chain-filters](https://github.com/IhorHorchakov/spring-security-jwt-authentication/blob/master/img/filter-chain-filters.png?raw=true)



-------
Useful links:

https://www.freecodecamp.org/news/user-authentication-methods-explained/

https://www.pingidentity.com/en/resources/blog/post/ultimate-guide-token-based-authentication.html

https://frontegg.com/blog/authentication

https://www.freecodecamp.org/news/user-authentication-methods-explained/



