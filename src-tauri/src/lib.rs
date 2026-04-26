use std::process::Child;
use std::sync::Mutex;

#[allow(dead_code)]
struct SidecarState(Mutex<Option<Child>>);

const SKIP_DIRS: &[&str] = &[
    ".git",
    "__pycache__",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
];
const SUPPORTED_EXTENSIONS: &[&str] = &["py", "js", "jsx", "ts", "tsx"];

#[tauri::command]
async fn pick_path(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    if let Some(folder) = app
        .dialog()
        .file()
        .set_title("Select directory containing source files")
        .blocking_pick_folder()
    {
        return Ok(Some(folder.to_string()));
    }
    let result = app
        .dialog()
        .file()
        .set_title("Select a Python, JavaScript, or TypeScript file")
        .add_filter("Source", SUPPORTED_EXTENSIONS)
        .blocking_pick_file();
    Ok(result.map(|p| p.to_string()))
}

#[tauri::command]
async fn read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
async fn list_py_files(dir: String) -> Result<Vec<String>, String> {
    list_source_files_inner(&dir)
}

#[tauri::command]
async fn list_source_files(path: String) -> Result<Vec<String>, String> {
    list_source_files_inner(&path)
}

fn list_source_files_inner(input: &str) -> Result<Vec<String>, String> {
    let path = std::path::Path::new(input);
    if path.is_file() {
        if is_supported_source(path) {
            return Ok(vec![input.to_string()]);
        }
        return Ok(vec![]);
    }
    let mut files = Vec::new();
    collect_source_files(path, &mut files)?;
    files.sort();
    Ok(files)
}

fn is_supported_source(path: &std::path::Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|ext| {
            SUPPORTED_EXTENSIONS
                .iter()
                .any(|supported| ext.eq_ignore_ascii_case(supported))
        })
        .unwrap_or(false)
}

fn collect_source_files(dir: &std::path::Path, out: &mut Vec<String>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !SKIP_DIRS.contains(&name) {
                collect_source_files(&path, out)?;
            }
        } else if is_supported_source(&path) {
            out.push(path.to_string_lossy().to_string());
        }
    }
    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_shell::init())
        .manage(SidecarState(Mutex::new(None)))
        .setup(|app| {
            // Dev mode: backend is started manually via uvicorn
            // Production: uncomment below to spawn bundled sidecar
            // let resource_path = app.path().resource_dir().unwrap().join("slayer-backend");
            // if resource_path.exists() {
            //     let child = Command::new(resource_path)
            //         .arg("--port").arg("18765")
            //         .spawn()
            //         .expect("Failed to start sidecar");
            //     *app.state::<SidecarState>().0.lock().unwrap() = Some(child);
            // }
            let _ = app;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            pick_path,
            read_file,
            list_py_files,
            list_source_files
        ])
        .run(tauri::generate_context!())
        .expect("error running SLAyer");
}
