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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| App::new()
        // enable logger
        .wrap(middleware::Logger::default())
        // setup ip filters
        .wrap(
            IPFilter::new()
                .allow(vec!["172.??.6*.12"])
                .block(vec!["192.168.1.222"])
        )
        // register simple route, handle all methods
        .service(web::resource("/").to(index))
    )
        .bind("0.0.0.0:8080")?;
    Ok(())
}
```
