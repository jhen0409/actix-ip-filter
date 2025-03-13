# actix-ip-filter

Actix Middleware for IP filter. Support glob pattern.

### Documentation

- [API Documentation](https://docs.rs/actix-ip-filter/)
- Cargo package: [actix-ip-filter](https://crates.io/crates/actix-ip-filter)

### Usage

```rust
use actix_web::{App, HttpServer, HttpRequest, web, middleware};
use actix_ip_filter::IPFilter;

async fn index(req: HttpRequest) -> &'static str {
    "Hello world"
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new()
        // enable logger
        .wrap(middleware::Logger::default())
        // setup ip filters
        .wrap(
            IPFilter::new()
                .allow(vec!["172.??.6*.12"])
                .block(vec!["192.168.1.222"])
                // Optionally use X-Forwarded-For with realip_remote_addr
                // .use_realip_remote_addr(true)
        )
        // register simple route, handle all methods
        .service(web::resource("/").to(index))
    )
        .bind("0.0.0.0:8080")?;
    Ok(())
}
```

### IP Address Extraction Options

The middleware provides several methods to extract the client IP address:

1. **Default**: Uses the peer address from the socket connection
2. **X-REAL-IP**: Extracts the IP from the X-REAL-IP header if present with `.x_real_ip(true)`
3. **X-Forwarded-For**: Uses Actix's built-in `realip_remote_addr()` method with `.use_realip_remote_addr(true)`, which extracts the client IP from the X-Forwarded-For header

When deployed behind proxies like AWS Elastic Load Balancer that set the X-Forwarded-For header instead of X-REAL-IP, using the `use_realip_remote_addr` option is recommended:

```rust
use actix_ip_filter::IPFilter;

let filter = IPFilter::new()
    .allow(vec!["192.168.1.*"])
    .use_realip_remote_addr(true);
```

### Limiting to certain paths

You can limit the allow/block actions to a certain set of patterns representing URL paths.
The following code will only allow/block to paths matching the patterns `/my/path*` and
`/my/other/*.csv`.

```rust
use actix_web::{App, HttpServer, HttpRequest, web, middleware};
use actix_ip_filter::IPFilter;

async fn i_am_protected() -> &'static str {
    "I am a protected resource"
}

async fn i_am_unprotected() -> &'static str {
    "I am NOT a protected resource"
}

#[tokio::main]
async fn main() -> std::io::Result<()> {


    HttpServer::new(|| App::new()
        // enable logger
        .wrap(middleware::Logger::default())
        // setup ip filters
        .wrap(
            IPFilter::new()
                .allow(vec!["172.??.6*.12"])
                .block(vec!["192.168.1.222"])
                .limit_to(vec!["/my/path/*"])
        )
        // register simple protected route
        .service(web::resource("/my/path/resource").to(i_am_protected))
        // register simple unprotected route
        .service(web::resource("/other/path/resource").to(i_am_unprotected))
    )
        .bind("0.0.0.0:8000");
    Ok(())
}
```

### Allow and block callbacks

You can add an allow handler and a block handler. These handlers will be called whenever a
request succeeds at passing an ip filter (allow handler) or it is blocked (block handler).
This last allows you to customize the error response. The callbacks will not be called on
unprotected paths.

#### The allow handler.

The allow handler must take three positional arguments and no return type:

```rust
use actix_ip_filter::IPFilter;
use actix_web::dev::ServiceRequest;

fn my_allow_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) {
    //Do smth
}
```

The parameters passed to the functions are borrows of the `IPFilter`, the ip of the request and
the request.

You can attach the handler to an `IPFilter` like this:

```rust
use actix_web::{App, HttpServer, HttpRequest, web, middleware};
use actix_ip_filter::IPFilter;
use actix_web::dev::ServiceRequest;

fn my_allow_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) {
    //Do smth
}

async fn i_am_protected() -> &'static str {
    "I am a protected resource"
}

async fn i_am_unprotected() -> &'static str {
    "I am NOT a protected resource"
}

#[tokio::main]
async fn main() -> std::io::Result<()> {


    HttpServer::new(|| App::new()
        // enable logger
        .wrap(middleware::Logger::default())
        // setup ip filters
        .wrap(
            IPFilter::new()
                .allow(vec!["172.??.6*.12"])
                .block(vec!["192.168.1.222"])
                .limit_to(vec!["/my/path/*"])
                .on_allow(my_allow_handler)
        )
        // register simple protected route
        .service(web::resource("/my/path/resource").to(i_am_protected))
        // register simple unprotected route
        .service(web::resource("/other/path/resource").to(i_am_unprotected))
    )
        .bind("0.0.0.0:8000");
    Ok(())
}
```

#### The block handler

The allow handler must take three positional arguments and and optional body response as a
response:

```rust
use actix_ip_filter::IPFilter;
use actix_web::dev::ServiceRequest;
use actix_web::HttpResponse;

fn my_block_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) -> Option<HttpResponse> {
    Some(HttpResponse::UseProxy().json("{\"result\": \"error\"}"))
}
```

The parameters passed to the functions are borrows of the `IPFilter`, the ip of the request and
the request.

If the handler returns None, then the default error response is used.
You can attach the handler to an `IPFilter` like this:

```rust
use actix_web::{App, HttpServer, HttpRequest, web, middleware};
use actix_ip_filter::IPFilter;
use actix_web::dev::ServiceRequest;
use actix_web::HttpResponse;

fn my_block_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) -> Option<HttpResponse> {
    Some(HttpResponse::UseProxy().json("{\"result\": \"error\"}"))
}

async fn i_am_protected() -> &'static str {
    "I am a protected resource"
}

async fn i_am_unprotected() -> &'static str {
    "I am NOT a protected resource"
}

#[tokio::main]
async fn main() -> std::io::Result<()> {


    HttpServer::new(|| App::new()
        // enable logger
        .wrap(middleware::Logger::default())
        // setup ip filters
        .wrap(
            IPFilter::new()
                .allow(vec!["172.??.6*.12"])
                .block(vec!["192.168.1.222"])
                .limit_to(vec!["/my/path/*"])
                .on_block(my_block_handler)
        )
        // register simple protected route
        .service(web::resource("/my/path/resource").to(i_am_protected))
        // register simple unprotected route
        .service(web::resource("/other/path/resource").to(i_am_unprotected))
    )
        .bind("0.0.0.0:8000");
    Ok(())
}
```

License: MIT
