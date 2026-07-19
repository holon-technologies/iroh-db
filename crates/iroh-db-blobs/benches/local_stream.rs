use std::{sync::Arc, time::Instant};

use iroh_db_blobs::{BlobEngine, IrohBlobStore};
use iroh_db_core::DomainId;
use iroh_db_security::DomainKey;
use tokio::io::AsyncReadExt as _;

fn main() {
    tokio::runtime::Runtime::new().unwrap().block_on(async {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(IrohBlobStore::load(directory.path()).await.unwrap());
        let engine = BlobEngine::new(
            store.clone(),
            DomainId::from_bytes([7; 32]),
            DomainKey::from_bytes([9; 32]),
        );
        let input = vec![42_u8; 64 * 1024 * 1024];
        let reference = engine.import_bytes(input, None).await.unwrap();
        let mut stream = engine.open(&reference).await.unwrap();
        let started = Instant::now();
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.unwrap();
        let elapsed = started.elapsed().as_secs_f64();
        println!(
            "iroh-db encrypted local stream: {:.1} MiB/s",
            f64::from(u32::try_from(output.len()).unwrap()) / (1024.0 * 1024.0) / elapsed
        );
        store.shutdown().await.unwrap();
    });
}
