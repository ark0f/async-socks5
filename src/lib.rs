use async_trait::async_trait;
use std::{
    convert::{TryFrom, TryInto},
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    string::FromUtf8Error,
};
use tokio::{
    io,
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpStream, ToSocketAddrs, UdpSocket},
};

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
    #[error("Wrong SOCKS version: {expected:?}, actual: {actual:?}")]
    WrongVersion { expected: Version, actual: Version },
    #[error("No acceptable methods")]
    NoAcceptableMethods,
    #[error("Unsuccessful reply: {0:?}")]
    Response(UnsuccessfulReply),
    #[error("String length is more than 255 bytes: {0:}")]
    TooLongString(String),
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Auth {
    pub username: String,
    pub password: String,
}

#[async_trait(? Send)]
trait ReadExt: AsyncReadExt + Unpin {
    async fn read_version(&mut self, cmp: Version) -> Result<()> {
        let version: Version = self.read_u8().await?.try_into()?;
        if version == cmp {
            Ok(())
        } else {
            Err(Error::WrongVersion {
                expected: cmp,
                actual: version,
            })
        }
    }

    async fn read_method(&mut self) -> Result<AuthMethod> {
        Ok(self.read_u8().await?.try_into()?)
    }

    async fn read_reserved(&mut self) -> Result<()> {
        let value = self.read_u8().await?;
        match value {
            0x00 => Ok(()),
            _ => Err(Error::InvalidReserved(value)),
        }
    }

    async fn read_target_addr(&mut self) -> Result<TargetAddr> {
        let atyp: Atyp = self.read_u8().await?.try_into()?;
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

    async fn read_final(&mut self) -> Result<TargetAddr> {
        self.read_version(Version::Socks5).await?;
        let reply: Reply = self.read_u8().await?.into();
        if let Reply::Unsuccessful(reply) = reply {
            return Err(Error::Response(reply));
        }
        self.read_reserved().await?;
        let addr = self.read_target_addr().await?;
        Ok(addr)
    }
}

#[async_trait(? Send)]
impl<T: AsyncReadExt + Unpin> ReadExt for T {}

#[async_trait(? Send)]
trait WriteExt: AsyncWriteExt + Unpin {
    async fn write_method(&mut self, method: AuthMethod) -> Result<()> {
        let value = match method {
            AuthMethod::None => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UsernamePassword => 0x02,
            AuthMethod::IanaReserved(value) => value,
            AuthMethod::Private(value) => value,
            AuthMethod::NoAcceptable => 0xff,
        };
        self.write_u8(value).await?;
        Ok(())
    }

    async fn write_reserved(&mut self) -> Result<()> {
        self.write_u8(0x00).await?;
        Ok(())
    }

    async fn write_target_addr(&mut self, target_addr: TargetAddr) -> Result<()> {
        match target_addr {
            TargetAddr::Ip(SocketAddr::V4(addr)) => {
                self.write_u8(Atyp::V4 as u8).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            TargetAddr::Ip(SocketAddr::V6(addr)) => {
                self.write_u8(Atyp::V6 as u8).await?;
                self.write_all(&addr.ip().octets()).await?;
                self.write_u16(addr.port()).await?;
            }
            TargetAddr::Domain(domain, port) => {
                self.write_u8(Atyp::Domain as u8).await?;
                self.write_string(domain).await?;
                self.write_u16(port).await?;
            }
        }
        Ok(())
    }

    async fn write_string(&mut self, str: String) -> Result<()> {
        let bytes = str.as_bytes();
        if bytes.len() > 255 {
            return Err(Error::TooLongString(str));
        }
        self.write_u8(bytes.len() as u8).await?;
        self.write_all(bytes).await?;
        Ok(())
    }

    async fn write_auth_version(&mut self) -> Result<()> {
        self.write_u8(0x01).await?;
        Ok(())
    }

    async fn write_methods(&mut self, methods: Vec<AuthMethod>) -> Result<()> {
        self.write_u8(methods.len() as u8).await?;
        for method in methods {
            self.write_method(method).await?;
        }
        Ok(())
    }
}

#[async_trait(? Send)]
impl<T: AsyncWriteExt + Unpin> WriteExt for T {}

#[derive(Debug, Eq, PartialEq)]
pub enum Version {
    Socks4 = 0x04,
    Socks5 = 0x05,
}

impl TryFrom<u8> for Version {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x04 => Ok(Version::Socks4),
            0x05 => Ok(Version::Socks5),
            _ => Err(Error::InvalidVersion(value)),
        }
    }
}

#[derive(Debug)]
pub enum AuthMethod {
    None,
    GssApi,
    UsernamePassword,
    IanaReserved(u8),
    Private(u8),
    NoAcceptable,
}

impl TryFrom<u8> for AuthMethod {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x00 => Ok(AuthMethod::None),
            0x01 => Ok(AuthMethod::GssApi),
            0x02 => Ok(AuthMethod::UsernamePassword),
            0x03..=0x7f => Ok(AuthMethod::IanaReserved(value)),
            0x80..=0xfe => Ok(AuthMethod::Private(value)),
            0xff => Ok(AuthMethod::NoAcceptable),
        }
    }
}

enum Command {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssociated = 0x03,
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Command::Connect),
            0x02 => Ok(Command::Bind),
            0x03 => Ok(Command::UdpAssociated),
            _ => Err(Error::InvalidCommand(value)),
        }
    }
}

enum Atyp {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl TryFrom<u8> for Atyp {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Atyp::V4),
            0x03 => Ok(Atyp::Domain),
            0x04 => Ok(Atyp::V6),
            _ => Err(Error::InvalidAtyp(value)),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
enum Reply {
    Successful,
    Unsuccessful(UnsuccessfulReply),
}

#[derive(Debug, Eq, PartialEq)]
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

impl From<u8> for Reply {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Reply::Successful,
            0x01 => Reply::Unsuccessful(UnsuccessfulReply::GeneralFailure),
            0x02 => Reply::Unsuccessful(UnsuccessfulReply::ConnectionNotAllowedByRules),
            0x03 => Reply::Unsuccessful(UnsuccessfulReply::NetworkUnreachable),
            0x04 => Reply::Unsuccessful(UnsuccessfulReply::HostUnreachable),
            0x05 => Reply::Unsuccessful(UnsuccessfulReply::ConnectionRefused),
            0x06 => Reply::Unsuccessful(UnsuccessfulReply::TtlExpired),
            0x07 => Reply::Unsuccessful(UnsuccessfulReply::CommandNotSupported),
            0x08 => Reply::Unsuccessful(UnsuccessfulReply::AddressTypeNotSupported),
            _ => Reply::Unsuccessful(UnsuccessfulReply::Unassigned(value)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl TargetAddr {
    // FIXME: until ToSocketAddrs is allowed to implement
    pub fn to_socket_addr(&self) -> String {
        match self {
            TargetAddr::Ip(addr) => addr.to_string(),
            TargetAddr::Domain(domain, port) => format!("{}:{}", domain, port),
        }
    }

    pub fn size(&self) -> usize {
        1 + // atyp
        2 + // port
            match self {
                TargetAddr::Ip(SocketAddr::V4(_)) => 4,
                TargetAddr::Ip(SocketAddr::V6(_)) => 16,
                TargetAddr::Domain(domain, _) => domain.len() + 1,
            }
    }
}

async fn init(
    socket: &mut TcpStream,
    command: Command,
    addr: TargetAddr,
    auth: Option<Auth>,
) -> Result<TargetAddr> {
    let mut socket = BufReader::new(socket);

    socket.write_u8(Version::Socks5 as u8).await?;
    let mut methods = Vec::with_capacity(2);
    methods.push(AuthMethod::None);
    if auth.is_some() {
        methods.push(AuthMethod::UsernamePassword);
    }
    socket.write_methods(methods).await?;

    socket.read_version(Version::Socks5).await?;
    let method: AuthMethod = socket.read_method().await?;
    match method {
        AuthMethod::None => {}
        // FIXME: until if let in match is stabilized
        AuthMethod::UsernamePassword if auth.is_some() => {
            let auth = auth.unwrap();

            socket.write_auth_version().await?;
            socket.write_string(auth.username).await?;
            socket.write_string(auth.password).await?;

            socket.read_auth_version().await?;
            socket.read_auth_status().await?;
        }
        AuthMethod::NoAcceptable => return Err(Error::NoAcceptableMethods),
        _ => return Err(Error::UnsupportedAuthMethod(method)),
    }

    socket.write_u8(Version::Socks5 as u8).await?;
    socket.write_u8(command as u8).await?;
    socket.write_reserved().await?;
    socket.write_target_addr(addr).await?;

    let addr = socket.read_final().await?;
    Ok(addr)
}

pub async fn connect(
    socket: &mut TcpStream,
    addr: TargetAddr,
    auth: Option<Auth>,
) -> Result<TargetAddr> {
    Ok(init(socket, Command::Connect, addr, auth).await?)
}

pub struct SocksListener {
    socket: TcpStream,
    proxy_addr: TargetAddr,
}

impl SocksListener {
    pub async fn bind(
        mut socket: TcpStream,
        addr: TargetAddr,
        auth: Option<Auth>,
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

pub struct SocksDatagram {
    socket: UdpSocket,
    proxy_addr: TargetAddr,
    _stream: TcpStream,
}

impl SocksDatagram {
    pub async fn associate<A: ToSocketAddrs, B: ToSocketAddrs>(
        proxy_addr: A,
        target_addr: B,
        auth: Option<Auth>,
    ) -> Result<Self> {
        let mut stream = TcpStream::connect(proxy_addr).await?;
        let local_addr = TargetAddr::Ip(SocketAddr::new(IpAddr::from([0, 0, 0, 0]), 0));
        let proxy_addr = init(&mut stream, Command::UdpAssociated, local_addr, auth).await?;
        let socket = UdpSocket::bind(target_addr).await?;
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

    pub async fn send_to(&mut self, buf: &[u8], addr: TargetAddr) -> Result<usize> {
        let socket_addr = addr.to_socket_addr();
        let mut bytes = Vec::with_capacity(
            2 // reserved
                + 1 // fragment id
                + addr.size() + buf.len(),
        );
        bytes.write_reserved().await?;
        bytes.write_reserved().await?;
        bytes.push(0x00);
        bytes.write_target_addr(addr).await?;
        bytes.extend_from_slice(buf);
        Ok(self.socket.send_to(&bytes, socket_addr).await?)
    }

    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, TargetAddr)> {
        let (len, _) = self.socket.recv_from(buf).await?;
        dbg!("recv_from");
        let mut cursor = Cursor::new(buf);
        cursor.read_reserved().await?;
        cursor.read_reserved().await?;
        let fragment_id = cursor.read_u8().await?;
        if fragment_id != 0 {
            return Err(Error::InvalidFragmentId(fragment_id));
        }
        let addr = cursor.read_target_addr().await?;
        Ok((len, addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROXY_ADDR: &str = "127.0.0.1:11223";

    #[tokio::test]
    async fn connect() -> Result<()> {
        let mut socket = TcpStream::connect(PROXY_ADDR).await?;
        super::connect(
            &mut socket,
            TargetAddr::Domain("google.com".to_string(), 80),
            Some(Auth {
                username: "hyper".to_string(),
                password: "proxy".to_string(),
            }),
        )
        .await?;
        Ok(())
    }

    async fn find_addr() -> Result<TargetAddr> {
        let mut socket = TcpStream::connect(PROXY_ADDR).await?;
        let addr = super::connect(
            &mut socket,
            TargetAddr::Domain("google.com".to_string(), 80),
            None,
        )
        .await?;
        Ok(addr)
    }

    #[tokio::test]
    async fn bind() -> Result<()> {
        let socket = TcpStream::connect(PROXY_ADDR).await?;
        let addr = find_addr().await?;
        let listener = SocksListener::bind(socket, addr, None).await?;

        let addr = listener.proxy_addr();
        let mut end = TcpStream::connect(addr.to_socket_addr()).await?;

        let mut conn = listener.accept().await?.0;
        conn.write_all(b"hello world").await?;

        let mut result = Vec::new();
        end.read_to_end(&mut result).await?;
        assert_eq!(result, b"hello world");

        Ok(())
    }

    #[tokio::test]
    async fn udp_associate() -> Result<()> {
        const DATA: &[u8] = b"hello world";

        let addr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 22334);

        let mut socks =
            SocksDatagram::associate(PROXY_ADDR, (IpAddr::from([127, 0, 0, 1]), 1234), None)
                .await?;
        let mut socket = UdpSocket::bind(addr).await?;

        let addr = TargetAddr::Ip(addr);
        let mut msg = vec![0; 3 + DATA.len() + addr.size()];

        socks.send_to(DATA, addr).await?;
        let (len, addr) = socket.recv_from(&mut msg).await?;
        assert_eq!(len, msg.len());

        socket.send_to(&msg, addr).await?;
        let (len, _) = socks.recv_from(&mut msg).await?;
        assert_eq!(len, msg.len());

        Ok(())
    }
}
