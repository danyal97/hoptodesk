use copypasta::{ClipboardContext, ClipboardProvider};
use std::{
    collections::HashMap,
    iter::FromIterator,
    process::Child,
    sync::{Arc, Mutex},
};
//use tokio::time::{Duration};
use sciter::Value;
use hbb_common::rand;
//use std::fs::write;
use hbb_common::{
    allow_err,
    config::{Config, LocalConfig, PeerConfig},
    log,
    //rendezvous_proto::*,
    tokio::{self},
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};
use hbb_common::get_version_number;
use tokio::runtime::Runtime;

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

pub type Children = Arc<Mutex<(bool, HashMap<(String, String), Child>)>>;
#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
    static ref CHILDREN : Children = Default::default();
}

struct UIHostHandler;

	
use std::env;

#[cfg(feature = "standalone")]
static DLL_BYTES: &[u8] = include_bytes!("../../sciter.dll");
#[cfg(feature = "standalone")]
static DLL_BYTESPM: &[u8] = include_bytes!("../../PrivacyMode.dll");
#[cfg(feature = "standalone")]
static DLL_BYTESPH: &[u8] = include_bytes!("../../privacyhelper.exe");

//struct UI;
struct UI {}

pub fn start(args: &mut [String]) {
    #[cfg(all(feature = "standalone", target_os = "windows"))]
	if !crate::platform::is_installed() {
		let dll_path = env::temp_dir().join("sciter.dll");
		let dll_path_str = dll_path.to_str().expect("Failed to convert path to string");
		sciter::set_library(dll_path_str).ok();
	} else {
		use std::path::Path;
		use std::fs;
		if !Path::new("sciter.dll").exists() {
			let dll_bytes = get_dll_bytes();
			let dll_path = env::temp_dir().join("sciter.dll");
			let dll_path_str = dll_path.to_str().expect("Failed to convert path to string");			
			if fs::metadata(&dll_path).is_err() {
				fs::write(&dll_path, dll_bytes).expect("Failed to write DLL file");
				sciter::set_library(dll_path_str).ok();
			}
			sciter::set_library(dll_path_str).ok();			
		}			
	}
	#[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/lib/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/lib/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                let _ = sciter_dll_path.to_string_lossy().to_string();
            }
        }
    }    
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(feature = "packui")]
    {
        let resources = include_bytes!("../target/resources.rc");
        frame.archive_handler(resources).expect("Invalid archive");
    }
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    let args_string = args.concat().replace("\"", "").replace("[", "").replace("]", "");
	
	if args.is_empty() || args_string.is_empty() || args[0] == "--qs" {
		//let children: Children = Default::default();
        //std::thread::spawn(move || check_zombie(children));
        std::thread::spawn(move || check_zombie());
        set_version();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--remoteupdate" {
		frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        //page = "install.html";
        if std::env::var("ProgramFiles").map_or(false, |pf| pf.contains("WindowsApps")) {
            return;
        } else if get_version_number(crate::VERSION) < get_version_number(&Config::get_option("api_version")) {
			let ui_instance = UI {};
			ui_instance.run_temp_update();
			return;
		}
		std::process::exit(0);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let cmd = iter.next().unwrap().clone();
        let id = iter.next().unwrap().clone();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
		let _teamid = iter.next().unwrap_or(&"".to_owned()).clone();
		let tokenexp = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
		if id == "hoptodesk:///" || id.is_empty()  {
			return;
		}
		if !tokenexp.is_empty() {
			std::fs::write(&Config::path("LastToken.toml"), tokenexp.clone()).expect("Failed to write tokenexp to file");
		}
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), tokenexp.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else if cfg!(target_os = "macos") && args_string.starts_with("hoptodesk://connect/") {
        if args_string.starts_with("hoptodesk://connect/") {
            let args_stringn = args_string.replace("hoptodesk://connect/", "");
            let mut iter = args_stringn.split('/');
            let id = iter.next().unwrap_or("").to_owned();
            let pass = iter.next().unwrap_or("").to_owned();
            let _teamid = iter.next().unwrap_or("").to_owned();
            let tokenexp = iter.next().unwrap_or("").to_owned();
            
            let args: Vec<String> = iter.map(|x| x.to_owned()).collect();

            if id.is_empty() {
                return;
            }

            if !tokenexp.is_empty() {
                std::fs::write(&Config::path("LastToken.toml"), tokenexp.clone())
                    .expect("Failed to write tokenexp to file");
            }
            
			frame.set_title(&id);
			frame.register_behavior("native-remote", move || {
				let handler = remote::SciterSession::new(
					"--connect".to_string(),
					id.clone(),
					pass.clone(),
					tokenexp.clone(),
					args.clone(),
				);
				#[cfg(not(any(feature = "flutter", feature = "cli")))]
				{
					*CUR_SESSION.lock().unwrap() = Some(handler.inner());
				}
				Box::new(handler)
			});	
        }

		page = "remote.html";
	} else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "packui")]
    frame.load_file(&format!("this://app/{}", page));
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(all(not(feature = "inline"), not(feature = "packui")))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
	frame.run_app();
}

#[cfg(feature = "standalone")]
pub fn get_dll_bytes() -> &'static [u8] {
    DLL_BYTES
}

#[cfg(feature = "standalone")]
pub fn get_dllpm_bytes() -> &'static [u8] {
    DLL_BYTESPM
}	

#[cfg(feature = "standalone")]
pub fn get_dllph_bytes() -> &'static [u8] {
    DLL_BYTESPH
}	


//struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        set_remote_id(id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false, false);
    }
/*
    fn update_me(&self, _path: String) {
        update_me(_path);
    }
*/
    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }
    /*
        fn get_license(&self) -> String {
            get_license()
        }
    */
    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }
/*
    fn using_public_server(&self) -> bool {
        using_public_server()
    }
*/
    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();

        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String) -> String {
        test_if_valid_server(host)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn get_config_option(&self, key: String) -> String {
        Config::get_option(&key)
    }

    fn set_config_option(&self, key: String, value: String) {
        Config::set_option(key, value);
    }

    fn requires_update(&self) -> bool {
        // Check if running from the Microsoft Store
        if std::env::var("ProgramFiles").map_or(false, |pf| pf.contains("WindowsApps")) {
            return false; // Return false if running from the Microsoft Store
        }
        //log::info!("from config {} Vs from wire {}", crate::VERSION, Config::get_option("api_version"));		
        get_version_number(crate::VERSION) < get_version_number(&Config::get_option("api_version"))
    }

    fn running_qs(&self) -> bool {
		if env::args().any(|arg| arg == "--qs") {
			true
		} else {
			false
		}
    }
	
	fn copy_text(&self, text: String) {
		copy_text(&text)
	}

    fn set_version_sync(&self) {
        set_version_sync()
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }
    
    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
		closing(x, y, w, h);
    }
	
    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

/*
    fn get_software_update_url(&self) -> String {
        get_software_update_url()
    }
*/
    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}", p.to_string_lossy())
    }
	

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn run_temp_update(&self) {
		#[cfg(windows)]
		{
			let exe_path = env::current_exe().expect("Failed to get current executable path").to_string_lossy().to_string();
			std::fs::write(&Config::path("UpdatePath.toml"), exe_path.clone()).expect("Failed to write update path");

			let mut tempexepath = std::env::temp_dir();
			tempexepath.push("HopToDesk-update.exe");
			log::info!("Saving update to: {:?}", tempexepath);
			let random_value = rand::random::<u64>().to_string();
			let url = format!("https://www.hoptodesk.com/update-windows?update={}", random_value);
			let rt = Runtime::new().unwrap();
			rt.block_on(async {
				log::info!("Downloading update...");
				let response = reqwest::get(url).await.expect("Error downloading update");
				let bytes = response.bytes().await.expect("Error reading token response");
				let _ = std::fs::remove_file(tempexepath.clone());
				let _ = std::fs::write(tempexepath.clone(), bytes);
				log::info!("Update saved.");
			});
		
			log::info!("Running update: {:?}", tempexepath.clone());
			let runuac = tempexepath.clone();
			let update_arg = if env::args().any(|arg| arg == "") {
				"--update"
			} else {
				"--updatefromremote"
			};
			
			if let Err(err) = crate::platform::windows::run_uac_hide(runuac.to_str().expect("Failed to convert executable path to string"), update_arg) {
				log::info!("UAC Run Error: {:?}", err);
			} else {
				log::info!("UAC Run success: {:?}", update_arg);
			}

			let args: Vec<String> = env::args().collect();
			if args.len() <= 1 || args[1] != "--remoteupdate" {
				std::process::exit(0);
			}
		}
    }
	
    fn get_teamid(&self) -> String {
		use std::path::Path;
		if Path::new(&Config::path("TeamID.toml")).exists() {
			if let Ok(body) = std::fs::read_to_string(Config::path("TeamID.toml")) {
				return body;
			} else {
				eprintln!("Error reading file");
			}
		
		}
		String::from("(none)")
    }

	#[cfg(any(target_os = "android", target_os = "ios"))]
    fn change_id(&self, id: String) {
		reset_async_job_status();
        let old_id = self.get_id();
		change_id_shared(id, old_id);
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn get_request(&self, url: String, header: String) {
        get_request(url, header)
    }
	
/*
    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }
*/
    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    /*
    fn get_api_server(&self) -> String {
        get_api_server()
    }
	*/
     fn has_hwcodec(&self) -> bool {
         has_hwcodec()
     }

    fn has_vram(&self) -> bool {
        has_vram()
    }
    
    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 200)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
                    
    fn get_custom_api_url(&self) -> String {
        if let Ok(Some(v)) = ipc::get_config("custom-api-url") {
            v
        } else {
            "".to_owned()
        }
    }

    fn set_custom_api_url(&self, url: String) {
        //ipc::set_config("custom-api-url", url);
		match ipc::set_config("custom-api-url", url) {
			Ok(()) => {},
			Err(e) => log::info!("Could not set custom API URL {e}"),
		}
		
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        //fn get_api_server();
        fn is_xfce();
        //fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        //fn get_license();
        fn test_if_valid_server(String);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        //fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        //fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
		fn run_temp_update();
		fn get_teamid();
        //fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
		fn get_request(String, String);
        //fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();        
        fn requires_update();
        fn running_qs();		
		fn set_version_sync();
		fn copy_text(String);
        fn get_config_option(String);
        fn set_config_option(String, String);
        fn get_custom_api_url();
        fn set_custom_api_url(String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

use serde::Deserialize;
#[derive(Deserialize)]
struct Version {
    winversion: String,
    linuxversion: String,
    macversion: String,
    none: String,
}

async fn get_version_(refresh_api: bool) -> String {
	if refresh_api {
		hbb_common::api::erase_api().await;
	}
	
	match hbb_common::api::call_api().await {
        Ok(v) => {
			let body =  serde_json::from_value::<Version>(v).expect("Could not get api_version.");
           
            if cfg!(windows) {
				return body.winversion
            } else if cfg!(macos) {
                return body.macversion
            } else if cfg!(linux) {
                return body.linuxversion
            } else {
                return body.none
            }
        }
        Err(e) =>  {
            log::info!("{:?}", e);
             return "".to_owned();
        }
    };
}

fn copy_text(text: &str) {
	#[cfg(not(target_os = "linux"))]
	{
		let mut ctx = ClipboardContext::new().unwrap();
		ctx.set_contents(text.to_owned()).unwrap();
	}
	#[cfg(target_os = "linux")]
	{
		use std::process::Command;
		use std::io::Write;

		unsafe {
			let mut command = Command::new("xclip");
			command.arg("-selection").arg("clipboard").stdin(std::process::Stdio::piped());

			if let Ok(mut child) = command.spawn() {
				if let Some(mut stdin) = child.stdin.take() {
					let _ = stdin.write_all(text.as_bytes());
				}
			}
		}
	}

}


pub fn set_version_sync() {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        Config::set_option("api_version".to_owned(), get_version_(true).await);
    });
}

#[tokio::main]
pub async fn set_version() {
    Config::set_option("api_version".to_owned(), get_version_(false).await)
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

#[inline]
pub fn new_remote(id: String, remote_type: String, force_relay: bool) {
    let mut lock = CHILDREN.lock().unwrap();
    let mut args = vec![format!("--{}", remote_type), id.clone()];
    if force_relay {
        args.push("".to_string()); // password
        args.push("--relay".to_string());
    }
    let key = (id.clone(), remote_type.clone());
    if let Some(c) = lock.1.get_mut(&key) {
        if let Ok(Some(_)) = c.try_wait() {
            lock.1.remove(&key);
        } else {
            if remote_type == "rdp" {
                allow_err!(c.kill());
                std::thread::sleep(std::time::Duration::from_millis(30));
                c.try_wait().ok();
                lock.1.remove(&key);
            } else {
                return;
            }
        }
    }
    match crate::run_me(args) {
        Ok(child) => {
            lock.1.insert(key, child);
        }
        Err(err) => {
            log::error!("Failed to spawn remote: {}", err);
        }
    }
}

#[inline]
pub fn recent_sessions_updated() -> bool {
    let mut children = CHILDREN.lock().unwrap();
    if children.0 {
        children.0 = false;
        true
    } else {
        false
    }
}

pub fn get_icon() -> String {
	#[cfg(target_os = "macos")]
    {
        let icon_data = include_bytes!("../res/128x128.png");
        let base64_str = base64::encode(icon_data);
        format!("data:image/png;base64,{}", base64_str)
    }
	#[cfg(not(target_os = "macos"))]
    {
        let icon_data = include_bytes!("../res/icon.ico");
        let base64_str = base64::encode(icon_data);
        format!("data:image/x-icon;base64,{}", base64_str)
    }
}