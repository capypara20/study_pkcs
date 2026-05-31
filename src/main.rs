use libloading::{Library, Symbol};
use object::{File, Object, ObjectSymbol, SymbolKind};
use std::{ffi::c_void, fs, os::raw::c_ulong, path::Path, ptr};

// PKCS#11 関数リスト構造体（主要な関数のみ定義）
#[repr(C)]
struct CK_FUNCTION_LIST {
    version: CK_VERSION,
    c_initialize: Option<unsafe extern "C" fn(*const c_void) -> c_ulong>,
    c_finalize: Option<unsafe extern "C" fn(*const c_void) -> c_ulong>,
    c_get_info: Option<unsafe extern "C" fn(*mut c_void) -> c_ulong>,
    c_get_slot_list: Option<unsafe extern "C" fn(u8, *mut c_ulong, *mut c_ulong) -> c_ulong>,
    // ... 他にもたくさんある（全部で70個くらい）
}

#[repr(C)]
struct CK_VERSION {
    major: u8,
    minor: u8,
}

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

fn call_get_function_list(lib: &Library) -> Result<(), Box<dyn std::error::Error>> {
    unsafe {
        // CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
        // 引数は「ポインタを入れる箱のアドレス」＝ポインタのポインタ(*mut *mut)
        type CGetFunctionList = unsafe extern "C" fn(*mut *mut c_void) -> c_ulong;
        let c_get_function_list: Symbol<CGetFunctionList> = lib.get(b"C_GetFunctionList")?;

        // ① 空の箱を用意（null で初期化）
        let mut function_list: *mut c_void = ptr::null_mut();

        // ② 箱のアドレス(&mut)を渡して呼ぶ
        let rv = c_get_function_list(&mut function_list);

        // ③ 2つの戻り値をチェックする
        println!("rv = {} (0なら成功)", rv);
        if rv == 0 && !function_list.is_null() {
            println!("関数リスト取得 成功! アドレス = {:?}", function_list);
            
            // ④ 生ポインタを CK_FUNCTION_LIST 構造体として解釈
            let fn_list = &*(function_list as *const CK_FUNCTION_LIST);
            
            // ⑤ バージョン情報を表示
            println!("PKCS#11 バージョン: {}.{}", fn_list.version.major, fn_list.version.minor);
            
            // ⑥ 個別の関数を呼び出す例
            if let Some(c_initialize) = fn_list.c_initialize {
                println!("C_Initialize を呼び出します...");
                let init_rv = c_initialize(ptr::null());
                println!("C_Initialize 結果: {}", init_rv);
            }
            
            if let Some(c_finalize) = fn_list.c_finalize {
                println!("C_Finalize を呼び出します...");
                let final_rv = c_finalize(ptr::null());
                println!("C_Finalize 結果: {}", final_rv);
            }
        } else {
            println!("失敗 (rv={}, nullか={})", rv, function_list.is_null());
        }
    }
    Ok(())
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
            call_get_function_list(&lib);
        }
        Err(e) => eprintln!("{}", e),
    }
}
