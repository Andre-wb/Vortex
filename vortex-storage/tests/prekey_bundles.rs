mod support;

use vortex_proto::prekey::bundle::stored::StoredBundle;
use vortex_storage::prekey::bundle::postgres::reader::PgBundleReader;
use vortex_storage::prekey::bundle::postgres::writer::PgBundleWriter;
use vortex_storage::prekey::bundle::reader::BundleReader;
use vortex_storage::prekey::bundle::writer::{BundleWriter, SaveOutcome};
use vortex_storage::prekey::device::directory::DeviceDirectory;
use vortex_storage::prekey::device::postgres::PgDeviceDirectory;
use vortex_storage::time::stamp::Stamp;

fn sample(device_id: Option<i64>, spk_id: i64) -> StoredBundle {
    StoredBundle {
        device_id,
        identity_key: vec![0x11; 32],
        signed_prekey: vec![0x22; 32],
        signed_prekey_sig: vec![0x33; 64],
        signed_prekey_id: spk_id,
        identity_key_ed: Some(vec![0x44; 32]),
        identity_key_sig: Some(vec![0x55; 64]),
        supports_v2: Some(true),
        device_x3dh_pub: Some(vec![0x66; 32]),
        device_sign_pub: Some(vec![0x77; 32]),
        device_cert_sig: Some(vec![0x88; 64]),
        client_device_id: Some("a".repeat(32)),
        device_kyber_pub: Some(vec![0x99; 1184]),
        device_kyber_sig: Some(vec![0xaa; 64]),
        device_kyber_id: Some(1),
    }
}

fn moment(seconds: i64, micros: u32) -> Stamp {
    Stamp::from_unix(seconds, micros).expect("отметка не собралась")
}

#[test]
fn a_bundle_returns_from_storage_exactly_as_it_went_in() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "bundle-roundtrip").await;
        let writer = PgBundleWriter::new(handle.clone());
        let reader = PgBundleReader::new(handle.clone());

        let bundle = sample(None, 7);
        let at = moment(1_785_834_930, 715_103);
        let outcome = writer.save(user_id, &bundle, at).await.expect("не записан");
        assert!(matches!(outcome, SaveOutcome::Created(_)));

        let found = reader
            .newest_of_user(user_id)
            .await
            .expect("не прочитан")
            .expect("бандла нет");
        assert_eq!(found.bundle, bundle);
        assert_eq!(found.created_at, at);
        assert_eq!(found.updated_at, at);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn publishing_again_for_the_same_device_updates_instead_of_adding() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "bundle-update").await;
        let writer = PgBundleWriter::new(handle.clone());
        let reader = PgBundleReader::new(handle.clone());

        let created = moment(1_785_834_930, 0);
        let first = writer
            .save(user_id, &sample(None, 1), created)
            .await
            .expect("не записан");

        let later = moment(1_785_838_530, 500_000);
        let second = writer
            .save(user_id, &sample(None, 2), later)
            .await
            .expect("не записан");

        assert_eq!(second, SaveOutcome::Updated(first.id()));
        let all = reader.all_of_user(user_id).await.expect("не прочитан");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].bundle.signed_prekey_id, 2);
        assert_eq!(all[0].created_at, created);
        assert_eq!(all[0].updated_at, later);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn a_bundle_without_a_device_never_collides_with_a_device_bundle() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "bundle-null-device").await;
        let client_device_id = "b".repeat(32);
        let device_id = support::make_device(&handle, user_id, &client_device_id).await;
        let writer = PgBundleWriter::new(handle.clone());
        let reader = PgBundleReader::new(handle.clone());
        let at = moment(1_785_834_930, 0);

        writer
            .save(user_id, &sample(None, 1), at)
            .await
            .expect("не записан");
        writer
            .save(user_id, &sample(Some(device_id), 2), at)
            .await
            .expect("не записан");

        let all = reader.all_of_user(user_id).await.expect("не прочитан");
        assert_eq!(all.len(), 2);

        let anonymous = reader
            .of_device(user_id, None)
            .await
            .expect("не прочитан")
            .expect("бандла нет");
        assert_eq!(anonymous.bundle.signed_prekey_id, 1);

        let named = reader
            .of_device(user_id, Some(device_id))
            .await
            .expect("не прочитан")
            .expect("бандла нет");
        assert_eq!(named.bundle.signed_prekey_id, 2);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn the_newest_bundle_of_a_user_is_the_one_updated_last() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "bundle-newest").await;
        let device_id = support::make_device(&handle, user_id, &"c".repeat(32)).await;
        let writer = PgBundleWriter::new(handle.clone());
        let reader = PgBundleReader::new(handle.clone());

        writer
            .save(
                user_id,
                &sample(Some(device_id), 1),
                moment(1_785_838_530, 0),
            )
            .await
            .expect("не записан");
        writer
            .save(user_id, &sample(None, 2), moment(1_785_834_930, 0))
            .await
            .expect("не записан");

        let newest = reader
            .newest_of_user(user_id)
            .await
            .expect("не прочитан")
            .expect("бандла нет");
        assert_eq!(newest.bundle.signed_prekey_id, 1);

        support::drop_user(&handle, user_id).await;
    });
}

#[test]
fn a_device_is_found_by_the_identifier_its_client_reports() {
    let runtime = support::runtime();
    runtime.block_on(async {
        let Some(handle) = support::handle().await else {
            return;
        };
        let user_id = support::make_user(&handle, "device-lookup").await;
        let client_device_id = "d".repeat(32);
        let device_id = support::make_device(&handle, user_id, &client_device_id).await;
        let directory = PgDeviceDirectory::new(handle.clone());

        assert_eq!(
            directory
                .device_of(user_id, &client_device_id)
                .await
                .expect("не прочитан"),
            Some(device_id)
        );
        assert_eq!(
            directory
                .device_of(user_id, &"e".repeat(32))
                .await
                .expect("не прочитан"),
            None
        );

        support::drop_user(&handle, user_id).await;
    });
}
