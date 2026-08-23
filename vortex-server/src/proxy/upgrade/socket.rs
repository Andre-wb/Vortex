use tokio::io::{AsyncRead, AsyncWrite};

pub trait UpstreamSocket: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> UpstreamSocket for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
