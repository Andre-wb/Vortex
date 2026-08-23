use tokio::io::copy_bidirectional;

use crate::proxy::upgrade::socket::UpstreamSocket;

pub async fn pump<C>(client: &mut C, upstream: &mut Box<dyn UpstreamSocket>)
where
    C: UpstreamSocket,
{
    match copy_bidirectional(client, upstream).await {
        Ok((to_upstream, to_client)) => {
            tracing::debug!(to_upstream, to_client, "туннель upgrade закрыт")
        }
        Err(error) => tracing::debug!("туннель upgrade оборван: {error}"),
    }
}
