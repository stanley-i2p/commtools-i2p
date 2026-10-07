use std::{collections::HashMap, path::PathBuf};

fn main() {
    println!("cargo:rerun-if-changed=assets/commtools-i2p.ico");

    #[cfg(target_os = "windows")]
    {
        let mut resource = winres::WindowsResource::new();
        resource.set_icon("assets/commtools-i2p.ico");
        resource
            .compile()
            .expect("failed to embed Windows application icon");
    }

    let libraries = HashMap::from([(
        "lucide".to_string(),
        PathBuf::from(lucide_slint::lib()),
    )]);
    let config = slint_build::CompilerConfiguration::new()
        .with_style("fluent-dark".into())
        .with_library_paths(libraries);
    slint_build::compile_with_config("ui/app-window.slint", config).expect("compile DeskComm UI");
}
