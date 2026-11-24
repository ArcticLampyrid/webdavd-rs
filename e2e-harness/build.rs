// `include_dir!` does not detect added or removed files in `images/` on stable
// Rust. Compile again if the directory changes.
fn main() {
    println!("cargo:rerun-if-changed=images");
}
