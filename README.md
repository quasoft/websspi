# websspi

*Note: Work in progress! Does **not** compile, **not** completed, **not** tested! (yet)*

`websspi` will be an HTTP middleware for Golang that uses Kerberos for single sign-on (SSO) authentication of browser based clients in a Windows environment.

The main goal is to create a middleware that performs authentication of HTTP requests without the need to create or use keytab files.

The middleware will implement the scheme defined by RFC4559 (SPNEGO-based HTTP Authentication in Microsoft Windows) to exchange security tokens via HTTP headers and will use SSPI (Security Support Provider Interface) to authenticate HTTP requests.

## Requirements

- The web browser should support Integrated Windows Authentication and have it enabled.
- SPNEGO HTTP provides no facilities for protecting the HTTP headers or data including the Authorization and WWW-Authenticate headers, which means that the HTTP server **MUST** enforce use of SSL to provide confidentiality to data in these headers!
