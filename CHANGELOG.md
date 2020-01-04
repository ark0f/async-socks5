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
