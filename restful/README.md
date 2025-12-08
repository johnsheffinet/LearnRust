# Requirements for rest app in rust

Develop a REST application in Rust that demonstrates CRUD operations with an in-memory data store.*  The application should also demonstrate the following capabilities.*  

1.  tls: *Show complete example to serve rest app over https with self-signed certificates and redirect http requests to https with axum-server.*  
2.  trc: *Show complete example to log method, uri, version, headers and body of request and version, status, headers and body of response with layer method in axum.*  
3.  auth: *Show complete example to authenticate and authorize request with axum-jwt-auth for layer method in axum and in-memory store for rbac.*  
4.  cache: *Show complete example to cache response in axum.*
    ### Key Concepts
    - axum-response-cache crate: This third-party middleware simplifies the integration of server-side response caching into your Axum application.
    - CacheLayer: This struct acts as a Tower layer that wraps your handlers, intercepting requests and responses to manage the cache.
    - cached::TimedSizedCache: The in-memory storage used for this example. The axum-response-cache crate requires any underlying cache store to implement specific traits from the cached crate.
    - Behavior: When a request hits the /hello/:name route, the middleware first checks if a valid cached entry exists. If found, it returns the cached response immediately, bypassing the handler function. Otherwise, it executes the handler, caches the successful response, and sends it back to the client. 
6.  cors: *Show complete example to prevent cross origin resource sharing in layer method in axum.*  
7.  csrf: *Show complete example to prevent cross site request forgery in layer method in axum.*  
8.  xss: *Show complete example to prevent cross site scripting with ammonia in axum.*  
9.  validate: *Show complete example to prevent cross site scripting with validator in axum.*  
10.  rate limit: *Show complete example to limit request rates with layer method in axum.*  
11.  size limit: *Show complete example to limit request sizes with layer method in axum.*  
12.  time limit: *Show complete example to limit response times with layer method in axum.* 
