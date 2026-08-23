use pyo3::prelude::*;
use vortex_storage::bot::inline::postgres::PgInlineResults;
use vortex_storage::bot::inline::results::InlineResults;
use vortex_storage::bot::scope::grants::ScopeGrants;
use vortex_storage::bot::scope::postgres::PgScopeGrants;
use vortex_storage::bot::webhook::postgres::reader::PgWebhookReader;
use vortex_storage::bot::webhook::postgres::writer::PgWebhookWriter;
use vortex_storage::bot::webhook::reader::WebhookReader;
use vortex_storage::bot::webhook::record::WebhookRecord;
use vortex_storage::bot::webhook::writer::WebhookWriter;
use vortex_storage::distributed::chunk::ChunkPlacement;
use vortex_storage::distributed::file::DistributedFile;
use vortex_storage::distributed::index::DistributedIndex;
use vortex_storage::distributed::postgres::index::PgDistributedIndex;
use vortex_storage::draft::drafts::Drafts;
use vortex_storage::draft::postgres::PgDrafts;
use vortex_storage::draft::record::DraftRecord;
use vortex_storage::push::unified::directory::UnifiedPushDirectory;
use vortex_storage::push::unified::postgres::PgUnifiedPushDirectory;
use vortex_storage::push::unified::subscription::UnifiedSubscription;

use crate::storage::api::{stamp, to_py_error};
use crate::storage::runtime;
use crate::storage::shared;

pub type PyWebhook = (String, String, String, i64, u32);
pub type PyChunk = (String, i64, i64, String, i64);
pub type PyDistributedFile = (String, i64, i64, i64, i64, u32, Vec<PyChunk>);
pub type PyDistributedEntry = (String, String, i64, i64, i64, u32);
pub type PyDraft = (String, i64, u32);
pub type PySubscription = (String, String, i64, u32, i64, bool);

#[pyfunction]
pub fn storage_webhook_of(py: Python<'_>, bot_id: i64) -> PyResult<Option<PyWebhook>> {
    let reader = PgWebhookReader::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(reader.of_bot(bot_id)))
        .map_err(to_py_error)?;
    Ok(found.map(|webhook| {
        (
            webhook.url,
            webhook.secret,
            webhook.events,
            webhook.created_at.unix_seconds(),
            webhook.created_at.micros(),
        )
    }))
}

#[pyfunction]
pub fn storage_save_webhook(
    py: Python<'_>,
    bot_id: i64,
    url: String,
    secret: String,
    events: String,
    seconds: i64,
    micros: u32,
) -> PyResult<()> {
    let writer = PgWebhookWriter::new(shared::handle().map_err(to_py_error)?);
    let webhook = WebhookRecord {
        bot_id,
        url,
        secret,
        events,
        created_at: stamp(seconds, micros)?,
    };
    py.allow_threads(|| runtime::block_on(writer.save(&webhook)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_forget_webhook(py: Python<'_>, bot_id: i64) -> PyResult<bool> {
    let writer = PgWebhookWriter::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(writer.forget(bot_id)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_bot_scopes(py: Python<'_>, bot_id: i64) -> PyResult<Vec<String>> {
    let grants = PgScopeGrants::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(grants.granted_to(bot_id)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_replace_bot_scopes(
    py: Python<'_>,
    bot_id: i64,
    scopes: Vec<String>,
) -> PyResult<()> {
    let grants = PgScopeGrants::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(grants.replace(bot_id, &scopes)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_inline_results(py: Python<'_>, bot_id: i64) -> PyResult<Option<String>> {
    let results = PgInlineResults::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(results.of_bot(bot_id)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_remember_inline(
    py: Python<'_>,
    bot_id: i64,
    answer: String,
    seconds: i64,
    micros: u32,
) -> PyResult<()> {
    let results = PgInlineResults::new(shared::handle().map_err(to_py_error)?);
    let at = stamp(seconds, micros)?;
    py.allow_threads(|| runtime::block_on(results.remember(bot_id, &answer, at)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_keep_newest_inline(py: Python<'_>, ceiling: i64) -> PyResult<u64> {
    let results = PgInlineResults::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(results.keep_newest(ceiling)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_draft_of(py: Python<'_>, user_id: i64, room_id: i64) -> PyResult<Option<PyDraft>> {
    let drafts = PgDrafts::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(drafts.of_member(user_id, room_id)))
        .map_err(to_py_error)?;
    Ok(found.map(|draft| {
        (
            draft.text,
            draft.updated_at.unix_seconds(),
            draft.updated_at.micros(),
        )
    }))
}

#[pyfunction]
pub fn storage_save_draft(
    py: Python<'_>,
    user_id: i64,
    room_id: i64,
    text: String,
    seconds: i64,
    micros: u32,
) -> PyResult<()> {
    let drafts = PgDrafts::new(shared::handle().map_err(to_py_error)?);
    let draft = DraftRecord {
        user_id,
        room_id,
        text,
        updated_at: stamp(seconds, micros)?,
    };
    py.allow_threads(|| runtime::block_on(drafts.save(&draft)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_clear_draft(py: Python<'_>, user_id: i64, room_id: i64) -> PyResult<bool> {
    let drafts = PgDrafts::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(drafts.clear(user_id, room_id)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_forget_stale_drafts(py: Python<'_>, seconds: i64, micros: u32) -> PyResult<u64> {
    let drafts = PgDrafts::new(shared::handle().map_err(to_py_error)?);
    let cutoff = stamp(seconds, micros)?;
    py.allow_threads(|| runtime::block_on(drafts.forget_untouched_since(cutoff)))
        .map_err(to_py_error)
}

fn placements(chunks: Vec<PyChunk>) -> Vec<ChunkPlacement> {
    chunks
        .into_iter()
        .map(
            |(chunk_hash, chunk_index, size, node_ip, node_port)| ChunkPlacement {
                chunk_hash,
                chunk_index,
                size,
                node_ip,
                node_port,
            },
        )
        .collect()
}

fn rendered(chunks: Vec<ChunkPlacement>) -> Vec<PyChunk> {
    chunks
        .into_iter()
        .map(|chunk| {
            (
                chunk.chunk_hash,
                chunk.chunk_index,
                chunk.size,
                chunk.node_ip,
                chunk.node_port,
            )
        })
        .collect()
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn storage_register_distributed(
    py: Python<'_>,
    file_hash: String,
    filename: String,
    total_size: i64,
    chunk_count: i64,
    uploader_id: i64,
    seconds: i64,
    micros: u32,
    chunks: Vec<PyChunk>,
) -> PyResult<()> {
    let index = PgDistributedIndex::new(shared::handle().map_err(to_py_error)?);
    let file = DistributedFile {
        file_hash,
        filename,
        total_size,
        chunk_count,
        uploader_id,
        created_at: stamp(seconds, micros)?,
        chunks: placements(chunks),
    };
    py.allow_threads(|| runtime::block_on(index.register(&file)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_locate_distributed(
    py: Python<'_>,
    file_hash: &str,
) -> PyResult<Option<PyDistributedFile>> {
    let index = PgDistributedIndex::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(index.locate(file_hash)))
        .map_err(to_py_error)?;
    Ok(found.map(|file| {
        (
            file.filename,
            file.total_size,
            file.chunk_count,
            file.uploader_id,
            file.created_at.unix_seconds(),
            file.created_at.micros(),
            rendered(file.chunks),
        )
    }))
}

#[pyfunction]
pub fn storage_list_distributed(py: Python<'_>) -> PyResult<Vec<PyDistributedEntry>> {
    let index = PgDistributedIndex::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(index.all()))
        .map_err(to_py_error)?;
    Ok(found
        .into_iter()
        .map(|file| {
            (
                file.file_hash,
                file.filename,
                file.total_size,
                file.chunk_count,
                file.created_at.unix_seconds(),
                file.created_at.micros(),
            )
        })
        .collect())
}

#[pyfunction]
pub fn storage_unified_push_of(py: Python<'_>, user_id: i64) -> PyResult<Vec<PySubscription>> {
    let directory = PgUnifiedPushDirectory::new(shared::handle().map_err(to_py_error)?);
    let found = py
        .allow_threads(|| runtime::block_on(directory.of_user(user_id)))
        .map_err(to_py_error)?;
    Ok(found
        .into_iter()
        .map(|subscription| {
            (
                subscription.endpoint,
                subscription.app_id,
                subscription.created_at.unix_seconds(),
                subscription.created_at.micros(),
                subscription.failures,
                subscription.active,
            )
        })
        .collect())
}

#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn storage_register_unified_push(
    py: Python<'_>,
    user_id: i64,
    endpoint: String,
    app_id: String,
    seconds: i64,
    micros: u32,
    failures: i64,
    active: bool,
) -> PyResult<()> {
    let directory = PgUnifiedPushDirectory::new(shared::handle().map_err(to_py_error)?);
    let subscription = UnifiedSubscription {
        user_id,
        endpoint,
        app_id,
        created_at: stamp(seconds, micros)?,
        failures,
        active,
    };
    py.allow_threads(|| runtime::block_on(directory.register(&subscription)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_unregister_unified_push(
    py: Python<'_>,
    user_id: i64,
    endpoint: &str,
) -> PyResult<bool> {
    let directory = PgUnifiedPushDirectory::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| runtime::block_on(directory.unregister(user_id, endpoint)))
        .map_err(to_py_error)
}

#[pyfunction]
pub fn storage_record_unified_delivery(
    py: Python<'_>,
    user_id: i64,
    endpoint: &str,
    failures: i64,
    active: bool,
) -> PyResult<()> {
    let directory = PgUnifiedPushDirectory::new(shared::handle().map_err(to_py_error)?);
    py.allow_threads(|| {
        runtime::block_on(directory.record_delivery(user_id, endpoint, failures, active))
    })
    .map_err(to_py_error)
}
