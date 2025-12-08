# Requirements for rest app in rust

Develop a REST application in Rust that demonstrates CRUD operations with an in-memory data store.*  The application should also demonstrate the following capabilities.*  

1. tls: *Show complete example to serve rest app over https with self-signed certificates and redirect http requests to https with axum-server.*  
2. trc: *Show complete example to log method, uri, version, headers and body of request and version, status, headers and body of response with layer method in axum.*  
3. auth: *Show complete example to authenticate and authorize request with axum-jwt-auth for layer method in axum and in-memory store for rbac.*  
4. cache: *Show complete example to cache response in axum.* Key concepts include: 
    - axum-response-cache crate: This third-party middleware simplifies the integration of server-side response caching into your Axum application. 
    - CacheLayer: This struct acts as a Tower layer that wraps your handlers, intercepting requests and responses to manage the cache. 
    - cached::TimedSizedCache: The in-memory storage used for this example. The axum-response-cache crate requires any underlying cache store to implement specific traits from the cached crate. 
    - Behavior: When a request hits the /hello/:name route, the middleware first checks if a valid cached entry exists. If found, it returns the cached response immediately, bypassing the handler function. Otherwise, it executes the handler, caches the successful response, and sends it back to the client. 
5. cors: *Show complete example to prevent cross origin resource sharing in layer method in axum.*  
6. csrf: *Show complete example to prevent cross site request forgery in layer method in axum.*  
7. xss: *Show complete example to prevent cross site scripting with ammonia in axum.*  Key concepts include: 
    - Sanitize on Input/Output: Always treat user input as untrusted. In the example, ammonia::clean is called on the raw comment string from the form data. 
    - Whitelist-based: ammonia operates on a whitelist of safe HTML tags (e.g., `<b>, <i>`) and attributes, effectively stripping out any potentially malicious elements like `<script>` or `onerror` event handlers. 
    - Use Templating Engines: When rendering data back to a page, a robust templating engine (like Tera or Askama) can automatically perform output encoding, providing an additional layer of defense by converting special characters into their HTML entities (e.g., `<` becomes `&lt;`). 
8. validate: *Show complete example to prevent cross site scripting with validator in axum.* 
9. rate limit: *Show complete example to limit request rates with layer method in axum.* Key concepts include: 
    - ServiceBuilder: This Tower utility helps compose multiple middleware layers cleanly. 
    - GovernorLayer: This is the core rate-limiting middleware that wraps your application's service. 
    - GovernorConfigBuilder: This is used to define the specifics of your rate limit, such as how many requests are allowed per time period and the burst size. 
    - PeerIpKeyExtractor: This is a key extractor that uses the client's IP address to differentiate users, ensuring each client is limited individually. 
    - .route_layer(...): This method applies the specified layers to the entire router and all its routes. 
    - Requests that exceed the defined limits will automatically receive an HTTP 429 Too Many Requests response. 
10. size limit: *Show complete example to limit request sizes with layer method in axum.* Key concepts include: 
    - DefaultBodyLimit::max(size): This is used to set the maximum allowed size for request bodies consumed by Axum extractors such as String, Json, and Form. 
    - Layer Application: The .layer() method applies the middleware. Middleware applied to a specific route (.route(...).layer(...)) runs only for that route, while a layer applied to the main Router (.layer(...) after all routes) acts as a global setting for all nested routes that haven't set their own specific limit. 
    - Error Handling: If a request exceeds the configured limit, Axum will automatically return an HTTP 413 Payload Too Large status code. 
11. time limit: *Show complete example to limit response times with layer method in axum.* Key concepts include: 
    - TimeoutLayer: This layer from tower-http wraps your service (the Axum router and its handlers) and imposes a time limit on the execution of the inner service. 
    - ServiceBuilder: It is recommended to use tower::ServiceBuilder when composing multiple layers. The layers are applied from top to bottom, meaning HandleErrorLayer will process errors from the TimeoutLayer. 
    - HandleErrorLayer: The TimeoutLayer returns a BoxError when a timeout occurs. This specific layer is necessary to catch that error and convert it into a valid HTTP Response that the user sees (e.g., 408 Request Timeout). 
    - slow_handler uses tokio::time: :sleep to simulate a long-running operation. Since it takes 5 seconds, it will be terminated by the TimeoutLayer and trigger handle_timeout_error. 
    - fast_handler completes within 0.5 seconds, so it responds normally. 
