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
//! #[actix_web::main]
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
//! ```
//!

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, error::ErrorForbidden, Error};
use futures_util::future::{ok, Future, Ready};
use glob::Pattern;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::rc::Rc;

fn wrap_pattern(list: Vec<&str>) -> Rc<Vec<Pattern>> {
    Rc::new(list.iter()
        .map(|rule| Pattern::new(rule).unwrap())
        .collect())
}

/// Middleware for filter IP of HTTP requests
#[derive(Default)]
pub struct IPFilter {
    use_x_real_ip: bool,
    allowlist: Rc<Vec<Pattern>>,
    blocklist: Rc<Vec<Pattern>>,
}


impl IPFilter {
    /// Construct `IPFilter` middleware with no arguments
    pub fn new() -> Self {
        Default::default()
    }

    /// Construct `IPFilter` middleware with the provided arguments
    pub fn new_with_opts(allowlist: Vec<&str>, blocklist: Vec<&str>, use_x_real_ip: bool) -> Self {
        IPFilter {
            use_x_real_ip,
            allowlist: wrap_pattern(allowlist),
            blocklist: wrap_pattern(blocklist),
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
}

impl<S, B> Transform<S> for IPFilter
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = IPFilterMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(IPFilterMiddleware {
            service,
            use_x_real_ip: self.use_x_real_ip,
            allowlist: Rc::clone(&self.allowlist),
            blocklist: Rc::clone(&self.blocklist),
        })
    }
}

pub struct IPFilterMiddleware<S> {
    service: S,
    use_x_real_ip: bool,
    allowlist: Rc<Vec<Pattern>>,
    blocklist: Rc<Vec<Pattern>>,
}

impl<S, B> Service for IPFilterMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let peer_addr_ip = req.peer_addr().unwrap().ip().to_string();
        let ip = if self.use_x_real_ip {
            match req.headers().get("X-REAL-IP") {
                Some(header) => String::from(header.to_str().unwrap()),
                None => peer_addr_ip,
            }
        } else {
            peer_addr_ip
        };

        if (!self.allowlist.is_empty() && !self.allowlist.iter().any(|re| re.matches(&ip)))
            || self.blocklist.iter().any(|re| re.matches(&ip))
        {
            return Box::pin(ok(req.error_response(ErrorForbidden("Forbidden"))));
        }

        Box::pin(self.service.call(req))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::StatusCode;
    use actix_web::test;

    #[actix_rt::test]
    async fn test_allowlist() {
        let ip_filter =
            IPFilter::new().allow(vec!["192.168.*.11?", "192.168.*.22?"]);
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
        let req = test::TestRequest::with_header("X-REAL-IP", "192.168.0.111")
            .peer_addr("192.168.0.222:8888".parse().unwrap())
            .to_srv_request();
        let resp = test::call_service(&mut fltr, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
