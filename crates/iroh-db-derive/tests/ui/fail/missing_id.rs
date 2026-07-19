use iroh_db_core::Lww;
use iroh_db_derive::IrohRecord;

#[derive(IrohRecord)]
struct Track {
    title: Lww<String>,
}

fn main() {}
