#[cfg(not(any(target_os = "android", target_os = "ios")))]
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    Emitter, Manager,
};

pub mod background;
pub mod permissions;
pub mod secure_dns;
pub mod tor_support;

#[cfg(any(
    target_os = "linux",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd"
))]
use webkit2gtk::{
    glib::prelude::ObjectExt, NotificationPermissionRequest, PermissionRequest,
    PermissionRequestExt, SettingsExt, UserMediaPermissionRequest, WebViewExt,
};

#[cfg(not(target_os = "android"))]
fn hide_window(window: &tauri::Window) {
    let _ = window.hide();
}

async fn secure_dns_watchdog_task(hostname: String) {
    secure_dns::spawn_dns_watchdog(hostname);
}

#[cfg(target_os = "android")]
fn hide_window(_window: &tauri::Window) {
    // Android n'a pas Window::hide()
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn check_updates_from_tray(app: tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
    let _ = app.emit("qx:check-updates", ());
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(permissions::init())
        .plugin(background::init())
        .plugin(tor_support::init());

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let builder = builder
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));

    builder
        .setup(|app| {
            // SECURITY (#4 privacy): DNS watchdog — detect resolver tampering.
            // The API origin is read from the runtime config env if present.
            if let Ok(origin) = std::env::var("QXP_SERVER_ORIGIN") {
                if let Some(hostname) = origin
                    .strip_prefix("https://")
                    .or_else(|| origin.strip_prefix("http://"))
                    .map(|h| h.split('/').next().unwrap_or("").to_string())
                {
                    if !hostname.is_empty()
                        && !hostname.starts_with("127.")
                        && !hostname.starts_with("localhost")
                    {
                        let _ = tokio::spawn(secure_dns_watchdog_task(hostname));
                    }
                }
            }

            #[cfg(not(any(target_os = "android", target_os = "ios")))]
            {
                let quit = MenuItem::with_id(app, "quit", "Quit QxChat", true, None::<&str>)?;

                let show = MenuItem::with_id(app, "show", "Open QxChat", true, None::<&str>)?;
                let check_updates =
                    MenuItem::with_id(app, "check_updates", "Check Updates", true, None::<&str>)?;

                let menu = Menu::with_items(app, &[&show, &check_updates, &quit])?;

                TrayIconBuilder::new()
                    .icon(app.default_window_icon().expect("missing app icon").clone())
                    .menu(&menu)
                    .on_menu_event(|app, event| match event.id.as_ref() {
                        "quit" => {
                            app.exit(0);
                        }

                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }

                        "check_updates" => {
                            check_updates_from_tray(app.clone());
                        }

                        _ => {}
                    })
                    .on_tray_icon_event(|tray, event| {
                        if let TrayIconEvent::Click {
                            button: MouseButton::Left,
                            ..
                        } = event
                        {
                            let app = tray.app_handle();

                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    })
                    .build(app)?;
            }

            // Linux WebKit permissions
            #[cfg(any(
                target_os = "linux",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            {
                let window = app
                    .get_webview_window("main")
                    .expect("main window not found");

                window.with_webview(|webview| {
                    let webview = webview.inner();

                    if let Some(settings) = webview.settings() {
                        settings.set_enable_media(true);
                        settings.set_enable_media_stream(true);
                        settings.set_enable_webrtc(true);
                        settings.set_media_playback_requires_user_gesture(false);
                    }

                    webview.connect_permission_request(|_, request: &PermissionRequest| {
                        if request.is::<UserMediaPermissionRequest>()
                            || request.is::<NotificationPermissionRequest>()
                        {
                            request.allow();
                            return true;
                        }

                        false
                    });
                })?;
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();

                hide_window(window);
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running QxChat");
}
