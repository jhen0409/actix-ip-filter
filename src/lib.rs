//! Actix Middleware for IP filter. Support glob pattern.
//!
//! ## Documentation
//! * [API Documentation](https://docs.rs/actix-ip-filter/)
//! * Cargo package: [actix-ip-filter](https://crates.io/crates/actix-ip-filter)
//! ## Usage
//! ```rust
//! use actix_web::{App, HttpServer, HttpRequest, web, middleware};
//! use actix_ip_filter::IPFilter;
//!
//! async fn index(req: HttpRequest) -> &'static str {
//!     "Hello world"
//! }
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     HttpServer::new(|| App::new()
//!         // enable logger
//!         .wrap(middleware::Logger::default())
//!         // setup ip filters
//!         .wrap(
//!             IPFilter::new()
//!                 .allow(vec!["172.??.6*.12"])
//!                 .block(vec!["192.168.1.222"])
//!         )
//!         // register simple route, handle all methods
//!         .service(web::resource("/").to(index))
//!     )
//!         .bind("0.0.0.0:8080")?;
//!     Ok(())
//! }
//!
//! ```
//! ## Limiting to certain paths
//! You can limit the allow/block actions to a certain set of patterns representing URL paths.
//! The following code will only allow/block to paths matching the patterns `/my/path*` and
//! `/my/other/*.csv`.
//! ```rust
//! use actix_web::{App, HttpServer, HttpRequest, web, middleware};
//! use actix_ip_filter::IPFilter;
//!
//! async fn i_am_protected() -> &'static str {
//!     "I am a protected resource"
//! }
//!
//! async fn i_am_unprotected() -> &'static str {
//!     "I am NOT a protected resource"
//! }
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!
//!
//!     HttpServer::new(|| App::new()
//!         // enable logger
//!         .wrap(middleware::Logger::default())
//!         // setup ip filters
//!         .wrap(
//!             IPFilter::new()
//!                 .allow(vec!["172.??.6*.12"])
//!                 .block(vec!["192.168.1.222"])
//!                 .limit_to(vec!["/my/path/*"])
//!         )
//!         // register simple protected route
//!         .service(web::resource("/my/path/resource").to(i_am_protected))
//!         // register simple unprotected route
//!         .service(web::resource("/other/path/resource").to(i_am_unprotected))
//!     )
//!         .bind("0.0.0.0:8000");
//!     Ok(())
//! }
//! ```
//! ## Allow and block callbacks
//! You can add an allow handler and a block handler. These handlers will be called whenever a
//! request succeeds at passing an ip filter (allow handler) or it is blocked (block handler).
//! This last allows you to customize the error response. The callbacks will not be called on
//! unprotected paths.
//!
//! ### The allow handler.
//! The allow handler must take three positional arguments and no return type:
//! ```rust
//! use actix_ip_filter::IPFilter;
//! use actix_web::dev::ServiceRequest;
//!
//! fn my_allow_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) {
//!     //Do smth
//! }
//!
//! ```
//! The parameters passed to the functions are borrows of the `IPFilter`, the ip of the request and
//! the request.
//!
//! You can attach the handler to an `IPFilter` like this:
//! ```rust
//! use actix_web::{App, HttpServer, HttpRequest, web, middleware};
//! use actix_ip_filter::IPFilter;
//! use actix_web::dev::ServiceRequest;
//!
//! fn my_allow_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) {
//!     //Do smth
//! }
//!
//! async fn i_am_protected() -> &'static str {
//!     "I am a protected resource"
//! }
//!
//! async fn i_am_unprotected() -> &'static str {
//!     "I am NOT a protected resource"
//! }
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!
//!
//!     HttpServer::new(|| App::new()
//!         // enable logger
//!         .wrap(middleware::Logger::default())
//!         // setup ip filters
//!         .wrap(
//!             IPFilter::new()
//!                 .allow(vec!["172.??.6*.12"])
//!                 .block(vec!["192.168.1.222"])
//!                 .limit_to(vec!["/my/path/*"])
//!                 .on_allow(my_allow_handler)
//!         )
//!         // register simple protected route
//!         .service(web::resource("/my/path/resource").to(i_am_protected))
//!         // register simple unprotected route
//!         .service(web::resource("/other/path/resource").to(i_am_unprotected))
//!     )
//!         .bind("0.0.0.0:8000");
//!     Ok(())
//! }
//! ```
//! ### The block handler
//! The allow handler must take three positional arguments and and optional body response as a
//! response:
//! ```rust
//! use actix_ip_filter::IPFilter;
//! use actix_web::dev::ServiceRequest;
//! use actix_web::HttpResponse;
//!
//! fn my_block_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) -> Option<HttpResponse> {
//!     Some(HttpResponse::UseProxy().json("{\"result\": \"error\"}"))
//! }
//! ```
//! The parameters passed to the functions are borrows of the `IPFilter`, the ip of the request and
//! the request.
//!
//! If the handler returns None, then the default error response is used.
//! You can attach the handler to an `IPFilter` like this:
//! ```rust
//! use actix_web::{App, HttpServer, HttpRequest, web, middleware};
//! use actix_ip_filter::IPFilter;
//! use actix_web::dev::ServiceRequest;
//! use actix_web::HttpResponse;
//!
//! fn my_block_handler(flt: &IPFilter, ip: &str, req: &ServiceRequest) -> Option<HttpResponse> {
//!     Some(HttpResponse::UseProxy().json("{\"result\": \"error\"}"))
//! }
//!
//! async fn i_am_protected() -> &'static str {
//!     "I am a protected resource"
//! }
//!
//! async fn i_am_unprotected() -> &'static str {
//!     "I am NOT a protected resource"
//! }
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!
//!
//!     HttpServer::new(|| App::new()
//!         // enable logger
//!         .wrap(middleware::Logger::default())
//!         // setup ip filters
//!         .wrap(
//!             IPFilter::new()
//!                 .allow(vec!["172.??.6*.12"])
//!                 .block(vec!["192.168.1.222"])
//!                 .limit_to(vec!["/my/path/*"])
//!                 .on_block(my_block_handler)
//!         )
//!         // register simple protected route
//!         .service(web::resource("/my/path/resource").to(i_am_protected))
//!         // register simple unprotected route
//!         .service(web::resource("/other/path/resource").to(i_am_unprotected))
//!     )
//!         .bind("0.0.0.0:8000");
//!     Ok(())
//! }
//! ```

use actix_service::{Service, Transform};
use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    error::ErrorForbidden,
    Error, HttpResponse,
};
use futures_util::future::{ok, FutureExt as _, LocalBoxFuture, Ready};
use glob::Pattern;
use std::rc::Rc;

fn wrap_pattern(list: Vec<&str>) -> Rc<Vec<Pattern>> {
    Rc::new(
        list.iter()
            .map(|rule| Pattern::new(rule).unwrap())
            .collect(),
    )
}

/// Middleware for filter IP of HTTP requests
pub struct IPFilter {
    use_x_real_ip: bool,
    allowlist: Rc<Vec<Pattern>>,
    blocklist: Rc<Vec<Pattern>>,
    limitlist: Rc<Vec<Pattern>>,
    allow_handler: Option<fn(&Self, &str, &ServiceRequest) -> ()>,
    block_handler: Option<fn(&Self, &str, &ServiceRequest) -> Option<HttpResponse>>,
}

impl Default for IPFilter {
    fn default() -> Self {
        Self {
            use_x_real_ip: false,
            allowlist: Rc::new(vec![]),
            blocklist: Rc::new(vec![]),
            limitlist: Rc::new(vec![]),
            allow_handler: None,
            block_handler: None,
        }
    }
}

impl IPFilter {
    /// Construct `IPFilter` middleware with no arguments
    pub fn new() -> Self {
        Default::default()
    }

    /// Construct `IPFilter` middleware with the provided arguments and no limiting pattern.
    pub fn new_with_opts(allowlist: Vec<&str>, blocklist: Vec<&str>, use_x_real_ip: bool) -> Self {
        IPFilter {
            use_x_real_ip,
            allowlist: wrap_pattern(allowlist),
            blocklist: wrap_pattern(blocklist),
            limitlist: wrap_pattern(vec![]),
            allow_handler: None,
            block_handler: None,
        }
    }

    /// Construct `IPFilter` middleware with the provided arguments and limiting patterns.
    pub fn new_with_opts_limited(
        allowlist: Vec<&str>,
        blocklist: Vec<&str>,
        limitlist: Vec<&str>,
        use_x_real_ip: bool,
    ) -> Self {
        IPFilter {
            use_x_real_ip,
            allowlist: wrap_pattern(allowlist),
            blocklist: wrap_pattern(blocklist),
            limitlist: wrap_pattern(limitlist),
            allow_handler: None,
            block_handler: None,
        }
    }

    /// Use `X-REAL-IP` header to check IP if it is found in request.
    pub fn x_real_ip(mut self, enabled: bool) -> Self {
        self.use_x_real_ip = enabled;
        self
    }

    /// Set allow IP list, it supported glob pattern. It will allow all if vec is empty.
    ///
    /// ## Example
    ///
    /// ```
    /// # use actix_ip_filter::IPFilter;
    /// let middleware = IPFilter::new()
    ///     .allow(vec!["127.??.6*.12", "!1.2.*.4'"]);
    /// ```
    pub fn allow(mut self, allowlist: Vec<&str>) -> Self {
        self.allowlist = wrap_pattern(allowlist);
        self
    }

    /// Set block IP list, it supported glob pattern.
    ///
    /// ## Example
    ///
    /// ```
    /// # use actix_ip_filter::IPFilter;
    /// let middleware = IPFilter::new()
    ///     .block(vec!["127.??.6*.12", "!1.2.*.4'"]);
    /// ```
    pub fn block(mut self, blocklist: Vec<&str>) -> Self {
        self.blocklist = wrap_pattern(blocklist);
        self
    }

    /// Set endpoint limit list, supporting glob pattern.
    ///
    /// ## Example
    ///
    /// ```
    /// # use actix_ip_filter::IPFilter;
    /// let middleware = IPFilter::new()
    ///     .limit_to(vec!["/path/to/protected/resource*", "/protected/file/type/*.csv"]);
    /// ```
    pub fn limit_to(mut self, limitlist: Vec<&str>) -> Self {
        self.limitlist = wrap_pattern(limitlist);
        self
    }

    /// Add allow handler.
    /// ## Example
    ///
    /// ```
    /// # use actix_ip_filter::IPFilter;
    /// # use actix_web::dev::{ServiceResponse, ServiceRequest};
    ///
    /// fn my_custom_handler(filter: &IPFilter, ip: &str, req: &ServiceRequest) {
    ///     // Do smth
    /// }
    ///
    /// let middleware = IPFilter::new()
    ///     .on_allow(my_custom_handler);
    /// ```
    pub fn on_allow(mut self, handler: fn(&Self, &str, &ServiceRequest) -> ()) -> Self {
        self.allow_handler = Some(handler);
        self
    }

    /// Add block handler.
    /// ## Example
    ///
    /// ```
    /// # use actix_ip_filter::IPFilter;
    /// # use actix_web::dev::{ServiceResponse, ServiceRequest};
    /// use actix_web::error::ErrorForbidden;
    /// use actix_web::HttpResponse;
    ///
    /// fn my_custom_handler(filter: &IPFilter, ip: &str, req: &ServiceRequest) -> Option<HttpResponse> {
    ///     Some(HttpResponse::Forbidden().body("My custom forbidden message!"))
    /// }
    ///
    /// let middleware = IPFilter::new()
    ///     .on_block(my_custom_handler);
    /// ```
    pub fn on_block(
        mut self,
        handler: fn(&Self, &str, &ServiceRequest) -> Option<HttpResponse>,
    ) -> Self {
        self.block_handler = Some(handler);
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for IPFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Transform = IPFilterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(IPFilterMiddleware {
            service: Rc::new(service),
            use_x_real_ip: self.use_x_real_ip,
            allowlist: Rc::clone(&self.allowlist),
            blocklist: Rc::clone(&self.blocklist),
            limitlist: Rc::clone(&self.limitlist),
            allow_handler: self.allow_handler,
            block_handler: self.block_handler,
        })
    }
}

#[derive(Clone)]
pub struct IPFilterMiddleware<S> {
    service: Rc<S>,
    use_x_real_ip: bool,
    allowlist: Rc<Vec<Pattern>>,
    blocklist: Rc<Vec<Pattern>>,
    limitlist: Rc<Vec<Pattern>>,
    allow_handler: Option<fn(&IPFilter, &str, &ServiceRequest) -> ()>,
    block_handler: Option<fn(&IPFilter, &str, &ServiceRequest) -> Option<HttpResponse>>,
}

impl<S, B> Service<ServiceRequest> for IPFilterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let peer_addr_ip = req.peer_addr().unwrap().ip().to_string();
        let ip = if self.use_x_real_ip {
            match req.headers().get("X-REAL-IP") {
                Some(header) => String::from(header.to_str().unwrap()),
                None => peer_addr_ip,
            }
        } else {
            peer_addr_ip
        };

        if (self.limitlist.is_empty() || self.limitlist.iter().any(|re| re.matches(req.path())))
            && ((!self.allowlist.is_empty() && !self.allowlist.iter().any(|re| re.matches(&ip)))
                || self.blocklist.iter().any(|re| re.matches(&ip)))
        {
            let response_opt: Option<HttpResponse> = if let Some(callback) = self.block_handler {
                callback(&middleware_to_filter(self), &ip, &req)
            } else {
                None
            };
            return if let Some(res) = response_opt {
                Box::pin(ok(req.into_response(res).map_into_right_body()))
            } else {
                Box::pin(ok(req.error_response(ErrorForbidden("Forbidden")).map_into_right_body()))
            };
        }

        if let Some(callback) = self.allow_handler {
            if self.limitlist.is_empty() || self.limitlist.iter().any(|re| re.matches(req.path())) {
                callback(&middleware_to_filter(self), &ip, &req)
            }
        }
        let service = Rc::clone(&self.service);
        async move {
            service
                .call(req)
                .await
                .map(|res| res.map_into_left_body())
        }
        .boxed_local()
    }
}

fn middleware_to_filter<S, B>(middleware: &IPFilterMiddleware<S>) -> IPFilter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    B: MessageBody + 'static,
{
    IPFilter {
        use_x_real_ip: middleware.use_x_real_ip,
        allowlist: middleware.allowlist.clone(),
        blocklist: middleware.blocklist.clone(),
        limitlist: middleware.limitlist.clone(),
        allow_handler: middleware.allow_handler,
        block_handler: middleware.block_handler,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use actix_web::test;

    #[actix_rt::test]
    async fn test_allowlist() {
        let ip_filter = IPFilter::new().allow(vec!["192.168.*.11?", "192.168.*.22?"]);
        let mut fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();

        let req = test::TestRequest::with_uri("test")
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = test::TestRequest::with_uri("test")
            .peer_addr("192.168.0.123:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn test_blocklist() {
        let ip_filter = IPFilter::new().block(vec!["192.168.*.2?3"]);
        let mut fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();

        let req = test::TestRequest::with_uri("test")
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let req = test::TestRequest::with_uri("test")
            .peer_addr("192.168.0.233:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_rt::test]
    async fn test_xrealip() {
        let ip_filter = IPFilter::new().allow(vec!["192.168.*.11?"]).x_real_ip(true);
        let mut fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();
        let req = test::TestRequest::default()
            .insert_header(("X-REAL-IP", "192.168.0.111"))
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_limitlist() {
        let ip_filter = IPFilter::new()
            .block(vec!["192.168.*.11?"])
            .limit_to(vec!["/protected/path/*"]);
        let mut fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();

        let req = test::TestRequest::with_uri("/protected/path/hello")
            .peer_addr("192.168.0.111:8888".parse().unwrap())
            .to_srv_request();

        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        let req = test::TestRequest::with_uri("/another/path")
            .peer_addr("192.168.0.111:8888".parse().unwrap())
            .to_srv_request();

        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_rt::test]
    async fn test_allow_handler() {
        let ip_filter = IPFilter::new()
            .allow(vec!["192.168.*.11?"])
            .limit_to(vec!["/protected/path/*"]);

        //let mut allow_count: u32 = 0;

        // Use closure instead of fn in order to capture ip_filter and allow_count.

        //let my_custom_handler = |filter: &IPFilter, ip: &str, req: &ServiceRequest| {
        //    allow_count += 1;
        //    assert_eq!(ip_filter, filter);
        //    assert_eq!(Pattern::new("192.168.*.11?").unwrap().matches(ip), true);
        //    assert_eq!(Pattern::new("/protected/path/*").unwrap().matches(req.path()), true);
        //};

        fn my_custom_handler(_filter: &IPFilter, ip: &str, req: &ServiceRequest) {
            assert_eq!(Pattern::new("192.168.*.11?").unwrap().matches(ip), true);
            assert_eq!(
                Pattern::new("/protected/path/*")
                    .unwrap()
                    .matches(req.path()),
                true
            );
        }

        // De-mut and attach custom handler to IPFilter.
        let ip_filter = ip_filter.on_allow(my_custom_handler);
        let mut fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();

        // Protected path and allowed ip should call the allow callback.
        let req = test::TestRequest::with_uri("/protected/path/hello")
            .peer_addr("192.168.0.111:8888".parse().unwrap())
            .to_srv_request();
        test::call_service(&mut fltr, req).await;
        //assert_eq!(allow_count, 1);

        // Unprotected path should not call the allow callback.
        let req = test::TestRequest::with_uri("/unprotected/path/hello")
            .peer_addr("192.168.0.111:8888".parse().unwrap())
            .to_srv_request();
        test::call_service(&mut fltr, req).await;
        //assert_eq!(allow_count, 1);

        // Protected path and blocked ip should not call the allow callback.
        let req = test::TestRequest::with_uri("/protected/path/hello")
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        test::call_service(&mut fltr, req).await;
        //assert_eq!(allow_count, 1);
    }

    #[actix_rt::test]
    async fn test_block_handler() {
        fn my_custom_handler(
            _filter: &IPFilter,
            ip: &str,
            req: &ServiceRequest,
        ) -> Option<HttpResponse> {
            assert_eq!(Pattern::new("192.168.*.11?").unwrap().matches(ip), false);
            assert_eq!(
                Pattern::new("/protected/path/*")
                    .unwrap()
                    .matches(req.path()),
                true
            );
            Some(HttpResponse::UseProxy().json("{\"result\": \"error\"}"))
        }

        let mut ip_filter = IPFilter::new()
            .allow(vec!["192.168.*.11?"])
            .limit_to(vec!["/protected/path/*"])
            .on_block(my_custom_handler);
        let mut fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();

        let req = test::TestRequest::with_uri("/protected/path/hello")
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::USE_PROXY);

        fn logging_handler(
            _filter: &IPFilter,
            _ip: &str,
            _req: &ServiceRequest,
        ) -> Option<HttpResponse> {
            None
        }

        ip_filter = ip_filter.on_block(logging_handler);
        fltr = ip_filter.new_transform(test::ok_service()).await.unwrap();

        let req = test::TestRequest::with_uri("/protected/path/hello")
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
