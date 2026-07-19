use iroh_db_derive::IrohRecord;

#[derive(IrohRecord)]
struct Track {
    #[iroh_db(id)]
    first: String,
    #[iroh_db(id)]
    second: String,
}

fn main() {}
