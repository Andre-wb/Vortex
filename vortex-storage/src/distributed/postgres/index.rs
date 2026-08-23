use async_trait::async_trait;

use crate::distributed::chunk::ChunkPlacement;
use crate::distributed::file::DistributedFile;
use crate::distributed::index::DistributedIndex;
use crate::distributed::postgres::row::FileRow;
use crate::error::Result;
use crate::ids::column_id;
use crate::pool::handle::PgHandle;
use crate::time::stamp::Stamp;

#[derive(Debug, Clone)]
pub struct PgDistributedIndex {
    handle: PgHandle,
}

impl PgDistributedIndex {
    pub fn new(handle: PgHandle) -> PgDistributedIndex {
        PgDistributedIndex { handle }
    }

    async fn chunks_of(&self, file_id: i32) -> Result<Vec<ChunkPlacement>> {
        let rows = sqlx::query!(
            r#"
            SELECT chunk_hash, chunk_index, size, node_ip, node_port
            FROM distributed_chunks
            WHERE file_id = $1
            ORDER BY chunk_index, id
            "#,
            file_id
        )
        .fetch_all(self.handle.pool())
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| ChunkPlacement {
                chunk_hash: row.chunk_hash,
                chunk_index: i64::from(row.chunk_index),
                size: i64::from(row.size),
                node_ip: row.node_ip,
                node_port: i64::from(row.node_port),
            })
            .collect())
    }
}

#[async_trait]
impl DistributedIndex for PgDistributedIndex {
    async fn register(&self, file: &DistributedFile) -> Result<()> {
        let uploader = column_id(file.uploader_id)?;
        let total_size = column_id(file.total_size)?;
        let chunk_count = column_id(file.chunk_count)?;
        let mut transaction = self.handle.pool().begin().await?;

        let stored = sqlx::query!(
            r#"
            INSERT INTO distributed_files (file_hash, filename, total_size, chunk_count, uploader_id, created_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (file_hash) DO UPDATE
            SET filename = EXCLUDED.filename,
                total_size = EXCLUDED.total_size,
                chunk_count = EXCLUDED.chunk_count,
                uploader_id = EXCLUDED.uploader_id,
                created_at = EXCLUDED.created_at
            RETURNING id
            "#,
            file.file_hash,
            file.filename,
            total_size,
            chunk_count,
            uploader,
            file.created_at.reading()
        )
        .fetch_one(&mut *transaction)
        .await?;

        sqlx::query!(
            r#"
            DELETE FROM distributed_chunks
            WHERE file_id = $1
            "#,
            stored.id
        )
        .execute(&mut *transaction)
        .await?;

        if !file.chunks.is_empty() {
            let mut hashes = Vec::with_capacity(file.chunks.len());
            let mut indexes = Vec::with_capacity(file.chunks.len());
            let mut sizes = Vec::with_capacity(file.chunks.len());
            let mut addresses = Vec::with_capacity(file.chunks.len());
            let mut ports = Vec::with_capacity(file.chunks.len());
            for chunk in &file.chunks {
                hashes.push(chunk.chunk_hash.clone());
                indexes.push(column_id(chunk.chunk_index)?);
                sizes.push(column_id(chunk.size)?);
                addresses.push(chunk.node_ip.clone());
                ports.push(column_id(chunk.node_port)?);
            }
            sqlx::query!(
                r#"
                INSERT INTO distributed_chunks (file_id, chunk_hash, chunk_index, size, node_ip, node_port)
                SELECT $1, placed.chunk_hash, placed.chunk_index, placed.size, placed.node_ip, placed.node_port
                FROM UNNEST($2::varchar[], $3::int4[], $4::int4[], $5::varchar[], $6::int4[])
                    AS placed(chunk_hash, chunk_index, size, node_ip, node_port)
                "#,
                stored.id,
                &hashes,
                &indexes,
                &sizes,
                &addresses,
                &ports
            )
            .execute(&mut *transaction)
            .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    async fn locate(&self, file_hash: &str) -> Result<Option<DistributedFile>> {
        let row = sqlx::query_as!(
            FileRow,
            r#"
            SELECT id, file_hash, filename, total_size, chunk_count, uploader_id, created_at
            FROM distributed_files
            WHERE file_hash = $1
            "#,
            file_hash
        )
        .fetch_optional(self.handle.pool())
        .await?;

        let epoch = Stamp::from_unix(0, 0)?;
        match row {
            None => Ok(None),
            Some(row) => {
                let chunks = self.chunks_of(row.id).await?;
                Ok(Some(row.into_file(chunks, epoch)))
            }
        }
    }

    async fn all(&self) -> Result<Vec<DistributedFile>> {
        let rows = sqlx::query_as!(
            FileRow,
            r#"
            SELECT id, file_hash, filename, total_size, chunk_count, uploader_id, created_at
            FROM distributed_files
            ORDER BY id
            "#
        )
        .fetch_all(self.handle.pool())
        .await?;

        let epoch = Stamp::from_unix(0, 0)?;
        let mut files = Vec::with_capacity(rows.len());
        for row in rows {
            let chunks = self.chunks_of(row.id).await?;
            files.push(row.into_file(chunks, epoch));
        }
        Ok(files)
    }
}
