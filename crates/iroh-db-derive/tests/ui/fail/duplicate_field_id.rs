use iroh_db_core::Lww;
use iroh_db_derive::IrohRecord;

#[derive(IrohRecord)]
struct Track {
    #[iroh_db(id, field_id = 7)]
    id: String,
    #[iroh_db(field_id = 7)]
    title: Lww<String>,
}

fn main() {}
