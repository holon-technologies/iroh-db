use iroh_db_derive::IrohRecord;

#[derive(IrohRecord)]
struct Track {
    #[iroh_db(id)]
    id: String,
    title: String,
}

fn main() {}
