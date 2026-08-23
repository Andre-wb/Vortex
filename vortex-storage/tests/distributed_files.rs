mod support;

use vortex_storage::distributed::chunk::ChunkPlacement;
use vortex_storage::distributed::file::DistributedFile;
use vortex_storage::distributed::index::DistributedIndex;
use vortex_storage::distributed::postgres::index::PgDistributedIndex;
use vortex_storage::time::stamp::Stamp;

fn moment(seconds: i64, micros: u32) -> Stamp {
    Stamp::from_unix(seconds, micros).expect("отметка не собралась")
}

fn placement(index: i64, port: i64) -> ChunkPlacement {
    ChunkPlacement {
        chunk_hash: format!("{index:064x}"),
        chunk_index: index,
        size: 1024 + index,
        node_ip: "10.0.0.1".to_owned(),
        node_port: port,
    }
}

fn sample(file_hash: String, uploader_id: i64, chunks: Vec<ChunkPlacement>) -> DistributedFile {
    DistributedFile {
        file_hash,
        filename: "notes.txt".to_owned(),
        total_size: 2048,
        chunk_count: chunks.len() as i64,
        uploader_id,
        created_at: moment(1_785_834_930, 715_103),
        chunks,
    }
}

#[test]
fn a_file_map_returns_from_storage_exactly_as_it_went_in() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "distributed-roundtrip").await;
        let index = PgDistributedIndex::new(handle.clone());
        let file_hash = support::unique_code();

        let file = sample(
            file_hash.clone(),
            user_id,
            vec![placement(0, 9000), placement(1, 9001)],
        );
        index.register(&file).await.expect("не записан");

        let found = index
            .locate(&file_hash)
            .await
            .expect("не прочитан")
            .expect("файла нет");
        assert_eq!(found, file);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn registering_a_file_again_replaces_its_chunks_instead_of_adding_them() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "distributed-replace").await;
        let index = PgDistributedIndex::new(handle.clone());
        let file_hash = support::unique_code();

        index
            .register(&sample(
                file_hash.clone(),
                user_id,
                vec![placement(0, 9000), placement(1, 9001), placement(2, 9002)],
            ))
            .await
            .expect("не записан");
        index
            .register(&sample(
                file_hash.clone(),
                user_id,
                vec![placement(0, 9100)],
            ))
            .await
            .expect("не записан");

        let found = index
            .locate(&file_hash)
            .await
            .expect("не прочитан")
            .expect("файла нет");
        assert_eq!(found.chunks, vec![placement(0, 9100)]);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn a_file_nobody_registered_is_not_found() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let index = PgDistributedIndex::new(handle.clone());
        assert!(index
            .locate(&support::unique_code())
            .await
            .expect("не прочитан")
            .is_none());
    });
}

#[test]
fn a_file_without_chunks_is_stored_and_read_back_empty() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "distributed-empty").await;
        let index = PgDistributedIndex::new(handle.clone());
        let file_hash = support::unique_code();

        index
            .register(&sample(file_hash.clone(), user_id, Vec::new()))
            .await
            .expect("не записан");

        let found = index
            .locate(&file_hash)
            .await
            .expect("не прочитан")
            .expect("файла нет");
        assert!(found.chunks.is_empty());

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn every_registered_file_shows_up_in_the_listing() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "distributed-list").await;
        let index = PgDistributedIndex::new(handle.clone());
        let file_hash = support::unique_code();

        index
            .register(&sample(
                file_hash.clone(),
                user_id,
                vec![placement(0, 9000)],
            ))
            .await
            .expect("не записан");

        let listed = index.all().await.expect("не прочитан");
        assert!(listed.iter().any(|file| file.file_hash == file_hash));

        support::drop_user(&handle, user_id).await;
    });
}
