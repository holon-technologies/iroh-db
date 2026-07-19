use iroh_db::{FetchOptions, IrohDb};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

#[tokio::test]
async fn lazy_stream_seeks_by_chunk_and_fails_over_between_providers() {
    let owner_dir = tempfile::tempdir().unwrap();
    let provider_dir = tempfile::tempdir().unwrap();
    let consumer_dir = tempfile::tempdir().unwrap();
    let owner = IrohDb::open(owner_dir.path()).await.unwrap();
    let seed = owner.domain_seed();
    let provider = IrohDb::create_in_domain(provider_dir.path(), &seed)
        .await
        .unwrap();
    let consumer = IrohDb::create_in_domain(consumer_dir.path(), &seed)
        .await
        .unwrap();
    for database in [&owner, &provider, &consumer] {
        database.trust_device(owner.author_id()).unwrap();
        database.trust_device(provider.author_id()).unwrap();
        database.trust_device(consumer.author_id()).unwrap();
    }

    let mut expected = vec![0_u8; 5 * 1024 * 1024 + 17];
    for (index, byte) in expected.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    let reference = owner
        .blobs()
        .import_bytes(expected.clone(), Some("application/octet-stream".into()))
        .await
        .unwrap();
    let owner_node = owner.start_sync().await.unwrap();
    let provider_node = provider.start_sync().await.unwrap();
    provider_node
        .fetch_blob_from(owner_node.addr(), &reference)
        .await
        .unwrap();
    let consumer_node = consumer.start_sync().await.unwrap();
    let (mut stream, metrics) = consumer_node
        .stream_blob_from(
            vec![owner_node.addr(), provider_node.addr()],
            &reference,
            FetchOptions {
                prefetch_chunks: 0,
                ..FetchOptions::default()
            },
        )
        .await
        .unwrap();

    owner_node.shutdown().await.unwrap();
    let mut beginning = vec![0_u8; 4096];
    stream.read_exact(&mut beginning).await.unwrap();
    assert_eq!(beginning, expected[..4096]);
    let tail_offset = expected.len() - 4096;
    stream
        .seek(std::io::SeekFrom::Start(tail_offset as u64))
        .await
        .unwrap();
    let mut tail = vec![0_u8; 4096];
    stream.read_exact(&mut tail).await.unwrap();
    assert_eq!(tail, expected[tail_offset..]);
    assert!(metrics.chunks_fetched() >= 3);
    assert!(metrics.provider_attempts() > metrics.chunks_fetched());

    provider_node.shutdown().await.unwrap();
    consumer_node.shutdown().await.unwrap();
    owner.close().await.unwrap();
    provider.close().await.unwrap();
    consumer.close().await.unwrap();
}
