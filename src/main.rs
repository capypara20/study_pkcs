use object::{Object, ObjectSymbol, SymbolKind};
use std::{fs, path::Path};

fn get_function_names<P: AsRef<Path>>(
    soft_path: P,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let path = soft_path.as_ref();
    let bin_data = fs::read(path)?;
    let file = object::File::parse(&*bin_data)?;

    let mut names = Vec::new();

    for symbol in file.dynamic_symbols() {
        if symbol.is_definition() && symbol.kind() == SymbolKind::Text {
            if let Ok(name) = symbol.name() {
                names.push(name.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

fn main() {
    let so_path = "lib/libsofthsm2.so";
    match get_function_names(so_path) {
        Ok(names) => {
            // C_ から始まる関数だけに絞る
            for name in names {
                if name.starts_with("C_") {
                    println!("{}", name);
                }
            }
        }
        Err(e) => eprintln!("ERROR: {}", e),
    }
}
