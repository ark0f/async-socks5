//! This library provides an asynchronous [SOCKS5] implementation.
//!
//! [SOCKS5]: https://tools.ietf.org/html/rfc1928

#![deny(missing_debug_implementations)]

use async_trait::async_trait;
use std::{
    borrow::Cow,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::FromUtf8Error,
};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

// Error and Result
// ********************************************************************************

/// The library's error type.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0:?}")]
    Io(
        #[from]
        #[source]
        io::Error,
    ),
    #[error("{0:?}")]
    FromUtf8(
        #[from]
        #[source]
        FromUtf8Error,
    ),
    #[error("Invalid SOCKS version: {0:x}")]
    InvalidVersion(u8),
    #[error("Invalid command: {0:x}")]
    InvalidCommand(u8),
    #[error("Invalid address type: {0:x}")]
    InvalidAtyp(u8),
    #[error("Invalid reserved bytes: {0:x}")]
    InvalidReserved(u8),
    #[error("Invalid authentication status: {0:x}")]
    InvalidAuthStatus(u8),
    #[error("Invalid authentication version of subnegotiation: {0:x}")]
    InvalidAuthSubnegotiation(u8),
    #[error("Invalid fragment id: {0:x}")]
    InvalidFragmentId(u8),
    #[error("Unsupported authentication method: {0:?}")]
    UnsupportedAuthMethod(AuthMethod),
    #[error("Wrong SOCKS version is 4, expected 5")]
    WrongVersion,
    #[error("No acceptable methods")]
    NoAcceptableMethods,
    #[error("Unsuccessful reply: {0:?}")]
    Response(UnsuccessfulReply),
    #[error("String length is more than 255 bytes: {0:}")]
    TooLongString(String),
}

/// The library's `Result` type alias.
pub type Result<T> = std::result::Result<T, Error>;

// Utilities
// ********************************************************************************

#[async_trait(? Send)]
trait ReadExt: AsyncReadExt + Unpin {
    async fn read_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        match value {
            0x04 => Err(Error::WrongVersion),
            0x05 => Ok(()),
            _ => Err(Error::InvalidVersion(value)),
        }
    }

    async fn read_method(&mut self) -> Result<AuthMethod> {
        let value = self.read_u8().await?;

        let method = match value {
            0x00 => AuthMethod::None,
            0x01 => AuthMethod::GssApi,
            0x02 => AuthMethod::UsernamePassword,
            0x03..=0x7f => AuthMethod::IanaReserved(value),
            0x80..=0xfe => AuthMethod::Private(value),
            0xff => return Err(Error::NoAcceptableMethods),
        };

        Ok(method)
    }

    async fn read_command(&mut self) -> Result<Command> {
        let value = self.read_u8().await?;

        let command = match value {
            0x01 => Command::Connect,
            0x02 => Command::Bind,
            0x03 => Command::UdpAssociate,
            _ => return Err(Error::InvalidCommand(value)),
        };

        Ok(command)
    }

    async fn read_atyp(&mut self) -> Result<Atyp> {
        let value = self.read_u8().await?;
        let atyp = match value {
            0x01 => Atyp::V4,
            0x03 => Atyp::Domain,
            0x04 => Atyp::V6,
            _ => return Err(Error::InvalidAtyp(value)),
        };
        Ok(atyp)
    }

    async fn read_reserved(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        match value {
            0x00 => Ok(()),
            _ => Err(Error::InvalidReserved(value)),
        }
    }

    async fn read_fragment_id(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value == 0x00 {
            Ok(())
        } else {
            Err(Error::InvalidFragmentId(value))
        }
    }

    async fn read_reply(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        let reply = match value {
            0x00 => return Ok(()),
            0x01 => UnsuccessfulReply::GeneralFailure,
            0x02 => UnsuccessfulReply::ConnectionNotAllowedByRules,
            0x03 => UnsuccessfulReply::NetworkUnreachable,
            0x04 => UnsuccessfulReply::HostUnreachable,
            0x05 => UnsuccessfulReply::ConnectionRefused,
            0x06 => UnsuccessfulReply::TtlExpired,
            0x07 => UnsuccessfulReply::CommandNotSupported,
            0x08 => UnsuccessfulReply::AddressTypeNotSupported,
            _ => UnsuccessfulReply::Unassigned(value),
        };

        Err(Error::Response(reply))
    }

    async fn read_target_addr(&mut self) -> Result<TargetAddr> {
        let atyp: Atyp = self.read_atyp().await?;

        let addr = match atyp {
            Atyp::V4 => {
                let mut ip = [0; 4];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                TargetAddr::Ip(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            Atyp::V6 => {
                let mut ip = [0; 16];
                self.read_exact(&mut ip).await?;
                let port = self.read_u16().await?;
                TargetAddr::Ip(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(ip),
                    port,
                    0,
                    0,
                )))
            }
            Atyp::Domain => {
                let str = self.read_string().await?;
                let port = self.read_u16().await?;
                TargetAddr::Domain(str, port)
            }
        };

        Ok(addr)
    }

    async fn read_string(&mut self) -> Result<String> {
        let len = self.read_u8().await?;
        let mut str = Vec::with_capacity(len as usize);
        self.read_exact(&mut str).await?;
        let str = String::from_utf8(str)?;
        Ok(str)
    }

    async fn read_auth_version(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value != 0x01 {
            return Err(Error::InvalidAuthSubnegotiation(value));
        }

        Ok(())
    }

    async fn read_auth_status(&mut self) -> Result<()> {
        let value = self.read_u8().await?;

        if value != 0x00 {
            return Err(Error::InvalidAuthStatus(value));
        }

        Ok(())
    }

    async fn read_selection_msg(&mut self) -> Result<AuthMethod> {
        self.read_version().await?;
        self.read_method().await
    }

    async fn read_final(&mut self) -> Result<TargetAddr> {
        self.read_version().await?;
        self.read_reply().await?;
        self.read_reserved().await?;
        let addr = self.read_target_addr().await?;
        Ok(addr)
    }
}

#[async_trait(? Send)]
impl<T: AsyncReadExt + Unpin> ReadExt for T {}

#[async_trait(? Send)]
trait WriteExt: AsyncWriteExt + Unpin {
    async fn write_version(&mut self) -> Result<()> {
        self.write_u8(0x05).await?;
        Ok(())
    }

    async fn write_method(&mut self, method: AuthMethod) -> Result<()> {
        let value = match method {
            AuthMethod::None => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::IanaReserved(value) => value,
            AuthMethod::Private(value) => value,
        };
        self.write_u8(value).await?;
        Ok(())
    }

    async fn write_command(&mut self, command: Command) -> Result<()> {
        self.write_u8(command as u8).await?;
        Ok(())
    }

    async fn write_atyp(&mut self, atyp: Atyp) -> Result<()> {
        self.write_u8(atyp as u8).await?;
        Ok(())
    }

    async fn write_reserved(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_fragment_id(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_target_addr(&mut self, target_addr: &TargetAddr) -> Result<()> {
        match target_addr {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                self.write_atyp(Atyp::V4).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                self.write_atyp(Atyp::V6).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            TargetAddr::Domain(domain, port) => {
                self.write_atyp(Atyp::Domain).await?;
                self.write_string(&domain).await?;
                self.write_u16(*port).await?;
            }
        }
        Ok(())
    }

    async fn write_string(&mut self, string: &str) -> Result<()> {
        let bytes = string.as_bytes();
        if bytes.len() > 255 {
            return Err(Error::TooLongString(string.to_owned()));
        }
        self.write_u8(bytes.len() as u8).await?;
        self.write_all(bytes).await?;
        Ok(())
    }

    async fn write_auth_version(&mut self) -> Result<()> {
        self.write_u8(0x01).await?;
        Ok(())
    }

    async fn write_methods(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_u8(methods.len() as u8).await?;
        for method in methods {
            self.write_method(*method).await?;
        }
        Ok(())
    }

    async fn write_selection_msg(&mut self, methods: &[AuthMethod]) -> Result<()> {
        self.write_version().await?;
        self.write_methods(&methods).await
    }

    async fn write_final(&mut self, command: Command, addr: &TargetAddr) -> Result<()> {
        self.write_version().await?;
        self.write_command(command).await?;
        self.write_reserved().await?;
        self.write_target_addr(addr).await
    }
}

#[async_trait(? Send)]
impl<T: AsyncWriteExt + Unpin> WriteExt for T {}

async fn username_password_auth(
    socket: &mut BufReader<&mut TcpStream>,
    auth: Auth<'_>,
) -> Result<()> {
    socket.write_auth_version().await?;
    socket.write_string(&auth.username).await?;
    socket.write_string(&auth.password).await?;

    socket.read_auth_version().await?;
    socket.read_auth_status().await
}

async fn init(
    socket: &mut TcpStream,
    command: Command,
    addr: &TargetAddr,
    auth: Option<Auth<'_>>,
) -> Result<TargetAddr> {
    let mut socket = BufReader::new(socket);

    let mut methods = Vec::with_capacity(2);
    methods.push(AuthMethod::None);
    if auth.is_some() {
        methods.push(AuthMethod::UsernamePassword);
    }
    socket.write_selection_msg(&methods).await?;

    let method: AuthMethod = socket.read_selection_msg().await?;
    match method {
        AuthMethod::None => {}
        // FIXME: until if let in match is stabilized
        AuthMethod::UsernamePassword if auth.is_some() => {
            username_password_auth(&mut socket, auth.unwrap()).await?;
        }
        _ => return Err(Error::UnsupportedAuthMethod(method)),
    }

    socket.write_final(command, &addr).await?;
    socket.read_final().await
}

// Types
// ********************************************************************************

/// Required for a username + password authentication.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub struct Auth<'a> {
    pub username: Cow<'a, str>,
    pub password: Cow<'a, str>,
}

/// A proxy authentication method.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum AuthMethod {
    /// No authentication required.
    None,
    /// GSS API.
    GssApi,
    /// A username + password authentication.
    UsernamePassword,
    /// IANA reserved.
    IanaReserved(u8),
    /// A private authentication method.
    Private(u8),
}

enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociate = 0x03,
}

enum Atyp {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x4,
}

/// An unsuccessful reply from a proxy server.
#[derive(Debug, Eq, PartialEq, Copy, Clone, Hash)]
pub enum UnsuccessfulReply {
    GeneralFailure,
    ConnectionNotAllowedByRules,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    Unassigned(u8),
}

/// A target address a proxy server will use to connect to.
#[derive(Debug, Eq, PartialEq, Clone, Hash)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    const MAX_SIZE: usize = 1 // atyp
        + 1 // domain len
        + 255 // domain
        + 2; // port

    // FIXME: until ToSocketAddrs is allowed to implement
    fn to_socket_addr(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.to_string(),
            TargetAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }

    fn size(&self) -> usize {
        1 + // atyp
            2 + // port
            match self {
                TargetAddr::Ip(SocketAddr::V4(_)) => 4,
                TargetAddr::Ip(SocketAddr::V6(_)) => 16,
                TargetAddr::Domain(domain, _) =>
                    1 // string len
                        + domain.len(),
            }
    }
}

// Public API
// ********************************************************************************

/// Proxifies a TCP connection. Performs the [`CONNECT`] command under the hood.
///
/// [`CONNECT`]: https://tools.ietf.org/html/rfc1928#page-6
///
/// ```no_run
/// use tokio::net::TcpStream;
/// use async_socks5::TargetAddr;
///
/// # use async_socks5::Result;
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
///
/// let mut stream = TcpStream::connect("my-proxy-server.com").await?;
/// let target_addr = TargetAddr::Domain("google.com".to_string(), 80);
/// async_socks5::connect(&mut stream, &target_addr, None).await?;
///
/// # Ok(())
/// # }
/// ```
pub async fn connect(
    socket: &mut TcpStream,
    addr: &TargetAddr,
    auth: Option<Auth<'_>>,
) -> Result<TargetAddr> {
    init(socket, Command::Connect, addr, auth).await
}

/// A listener that accepts TCP connections through a proxy.
///
/// ```no_run
/// use tokio::net::TcpStream;
/// use async_socks5::{TargetAddr, SocksListener};
///
/// # use async_socks5::Result;
/// # #[tokio::main]
/// # async fn main() -> Result<()> {
///
/// let mut stream = TcpStream::connect("my-proxy-server.com").await?;
/// let target_addr = TargetAddr::Domain("ftp-server.org".to_string(), 21);
/// let (stream, addr) = SocksListener::bind(stream, &target_addr, None).await?.accept().await?;
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct SocksListener {
    socket: TcpStream,
    proxy_addr: TargetAddr,
}

impl SocksListener {
    /// Creates `SocksListener`. Performs the [`BIND`] command under the hood.
    ///
    /// [`BIND`]: https://tools.ietf.org/html/rfc1928#page-6
    pub async fn bind(
        mut socket: TcpStream,
        addr: &TargetAddr,
        auth: Option<Auth<'_>>,
    ) -> Result<SocksListener> {
        let addr = init(&mut socket, Command::Bind, addr, auth).await?;
        Ok(Self {
            socket,
            proxy_addr: addr,
        })
    }

    pub fn proxy_addr(&self) -> &TargetAddr {
        &self.proxy_addr
    }

    pub async fn accept(mut self) -> Result<(TcpStream, TargetAddr)> {
        let addr = self.socket.read_final().await?;
        Ok((self.socket, addr))
    }
}

/// A UDP socket that sends packets through a proxy.
#[derive(Debug)]
pub struct SocksDatagram {
    socket: UdpSocket,
    proxy_addr: TargetAddr,
    _stream: TcpStream,
}

impl SocksDatagram {
    /// Creates `SocksDatagram`. Performs [`UDP ASSOCIATE`] under the hood.
    ///
    /// [`UDP ASSOCIATE`]: https://tools.ietf.org/html/rfc1928#page-7
    pub async fn associate<A: ToSocketAddrs>(
        proxy_addr: A,
        socket: UdpSocket,
        auth: Option<Auth<'_>>,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let unknown_yet = TargetAddr::Ip(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0));
        let proxy_addr = init(&mut stream, Command::UdpAssociate, &unknown_yet, auth).await?;
        socket.connect(proxy_addr.to_socket_addr()).await?;
        Ok(Self {
            socket,
            proxy_addr,
            _stream: stream,
        })
    }

    pub fn proxy_addr(&self) -> &TargetAddr {
        &self.proxy_addr
    }

    pub fn get_ref(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn get_mut(&mut self) -> &mut UdpSocket {
        &mut self.socket
    }

    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }

    pub async fn send_to(&mut self, buf: &[u8], addr: &TargetAddr) -> Result<usize> {
        let mut cursor = Cursor::new(Self::alloc_buf(addr.size(), buf.len()));
        cursor.write_reserved().await?;
        cursor.write_reserved().await?;
        cursor.write_fragment_id().await?;
        cursor.write_target_addr(addr).await?;
        cursor.write_all(buf).await?;
        let bytes = cursor.into_inner();
        Ok(self.socket.send(&bytes).await?)
    }

    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, TargetAddr)> {
        let mut bytes = Self::alloc_buf(TargetAddr::MAX_SIZE, buf.len());
        let len = self.socket.recv(&mut bytes).await?;

        let mut cursor = Cursor::new(bytes);
        cursor.read_reserved().await?;
        cursor.read_reserved().await?;
        cursor.read_fragment_id().await?;
        let addr = cursor.read_target_addr().await?;
        let header_len = cursor.position() as usize;
        cursor.read_exact(buf).await?;
        Ok((len - header_len, addr))
    }

    fn alloc_buf(addr_size: usize, buf_len: usize) -> Vec<u8> {
        vec![
            0;
            2 // reserved
                + 1 // fragment id
                + addr_size
                + buf_len
        ]
    }
}

// Tests
// ********************************************************************************

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY_ADDR: &str = "127.0.0.1:1080";
    const PROXY_AUTH_ADDR: &str = "127.0.0.1:1081";
    const DATA: &[u8] = b"Hello, world!";

    async fn connect(addr: &str, auth: Option<Auth<'_>>) {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        super::connect(
            &mut socket,
            &TargetAddr::Domain("google.com".to_string(), 80),
            auth,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn connect_auth() {
        connect(
            PROXY_AUTH_ADDR,
            Some(Auth {
                username: Cow::from("hyper"),
                password: Cow::from("proxy"),
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn connect_no_auth() {
        connect(PROXY_ADDR, None).await;
    }

    #[should_panic = "ConnectionNotAllowedByRules"]
    #[tokio::test]
    async fn connect_no_auth_panic() {
        connect(PROXY_AUTH_ADDR, None).await;
    }

    #[tokio::test]
    async fn bind() {
        let server_addr = TargetAddr::Domain("127.0.0.1".to_string(), 80);

        let client = TcpStream::connect(PROXY_ADDR).await.unwrap();
        let client = SocksListener::bind(client, &server_addr, None)
            .await
            .unwrap();

        let server_addr = client.proxy_addr.to_socket_addr();
        let mut server = TcpStream::connect(&server_addr).await.unwrap();

        let (mut client, _) = client.accept().await.unwrap();

        server.write_all(DATA).await.unwrap();

        let mut buf = [0; DATA.len()];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, DATA);
    }

    #[tokio::test]
    async fn udp_associate() {
        let client = UdpSocket::bind("127.0.0.1:2345").await.unwrap();
        let mut client = SocksDatagram::associate(PROXY_ADDR, client, None)
            .await
            .unwrap();

        let server_addr: SocketAddr = "127.0.0.1:23456".parse().unwrap();
        let mut server = UdpSocket::bind(server_addr).await.unwrap();
        let server_addr = TargetAddr::Ip(server_addr);

        let mut buf = vec![0; DATA.len()];
        client.send_to(DATA, &server_addr).await.unwrap();
        let (len, addr) = server.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, buf.len());
        assert_eq!(buf.as_slice(), DATA);

        let mut buf = vec![0; DATA.len()];
        server.send_to(DATA, addr).await.unwrap();
        let (len, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(len, buf.len());
        assert_eq!(buf.as_slice(), DATA);
    }
}
