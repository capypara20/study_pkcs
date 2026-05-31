use libloading::{Library, Symbol};
use object::{File, Object, ObjectSymbol, SymbolKind};
use std::{ffi::c_void, fs, os::raw::c_ulong, path::Path, ptr};

fn load_library<P: AsRef<Path>>(soft_path: P) -> Result<Library, Box<dyn std::error::Error>> {
    let lib = unsafe { Library::new(soft_path.as_ref())? };
    Ok(lib)
}

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

fn call_initialize(lib: &Library) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        type CInitialize = unsafe extern "C" fn(*const c_void) -> c_ulong;
        let c_init: Symbol<CInitialize> = lib.get(b"C_GetFunctionList")?;
        let rv = c_init(ptr::null());
        println!("{}", rv);
    }
    Ok(())
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

    match load_library(so_path) {
        Ok(lib) => {
            if let Err(e) = call_initialize(&lib) {
                eprintln!("ERROR: {}", e);
            }
        }
        Err(e) => eprintln!("{}", e),
    }
}
