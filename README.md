<div align="center">
  <h1>async-socks5</h1>
  
  <a href="https://github.com/ark0f/async-socks5/actions">
    <img src="https://github.com/ark0f/async-socks5/workflows/CI/badge.svg">
  </a>
  
  <a href="*">
    <img src="https://img.shields.io/crates/l/async-socks5.svg">
  </a>
  
  <a href="https://crates.io/crates/async-socks5">
    <img src="https://img.shields.io/crates/v/async-socks5.svg">
  </a>
  
  <a href="https://docs.rs/async-socks5">
    <img src="https://docs.rs/async-socks5/badge.svg">
  </a>
  
  An `async`/`.await` [SOCKS5](https://tools.ietf.org/html/rfc1928) implementation.
</div>

## Examples
Connect to `google.com:80` through `my-proxy-server.com:54321`:

```rust
use tokio::net::TcpStream;
use tokio::io::BufStream;
use async_socks5::{connect, Result};

#[tokio::main]
async fn main() -> Result<()> {
  let stream = TcpStream::connect("my-proxy-server.com:54321").await?;
  let mut stream = BufStream::new(stream);
  connect(&mut stream, ("google.com", 80), None).await?;
}
```

[More examples](https://docs.rs/async-socks5).

# [Changelog](https://github.com/ark0f/async-socks5/blob/master/CHANGELOG.md)

# License
async-socks5 under either of:

* [Apache License 2.0](https://github.com/ark0f/async-socks5/blob/master/LICENSE-APACHE.md)
* [MIT](https://github.com/ark0f/async-socks5/blob/master/LICENSE-MIT.md)

at your option.
