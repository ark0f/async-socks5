# v0.5.1 (2022-03-03)
Fix processing of `DOMAINNAME` address type

# v0.5.0 (2020-12-26)
Update to tokio 1.0

# v0.4.0 (2020-10-16)
Update to tokio 0.3
`send_to` and `recv_from` use `&self` now, so you can use something like `Arc` to make send and receive halves

# v0.3.2 (2020-08-04)
Add split API for `SocksDatagram`

# v0.3.1 (2020-03-18)
Fix `thiserror` crate incorrectly displaying foreign errors

# v0.3.0 (2020-01-05)
Now you can use anything that implement `AsyncRead` and `AsyncWrite`

# v0.2.1 (2020-01-04)
Fix futures have no `Send` trait

# v0.2.0 (2019-12-31)
* Rename `TargetAddr` to `AddrKind`
* Implement `From<...>` for `AddrKind` and consume `Into<AddrKind>` in method arguments
* Update `Error`
* `SocksDatagram::associate` now consume `TcpStream` instead of `ToSocketAddrs` and can access association address
* Add `new` method for `Auth`

# v0.1.1 (2019-12-25)
* Increase inner buffer size when receiving UDP datagram
* Fix crate name in documentation
* Set minimum versions of dependencies

# v0.1.0 (2019-12-21)
Initial commit
