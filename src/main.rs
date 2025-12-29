mod service_handler;
mod registry_handler;
mod filesystem_handler;

use service_handler::{GetServices, CheckServices};
use filesystem_handler::{CanEditDirectory, TargetPaths};
use registry_handler::{check_install_registry, check_uac_security};

const INFO_HEAD: &str = "\x1b[36m[i]\x1b[0m ";
const IMPT_HEAD: &str = "\x1b[34m[#]\x1b[0m ";
const MISC_HEAD: &str = "\x1b[35m[*]\x1b[0m ";
const EROR_HEAD: &str = "\x1b[31m[!]\x1b[0m ";
const PASS_HEAD: &str = "\x1b[32m[+]\x1b[0m ";
const FAIL_HEAD: &str = "\x1b[91m[-]\x1b[0m ";

fn main()
{
    println!("{}Start of program.", IMPT_HEAD);
    // Check "Always install elevated" permissions
    println!("{}Checking for MSI installer escilation...", INFO_HEAD);
    if check_install_registry() == true
    {
        println!("{}Computer is vulnerable to MSI installer file escilation!", PASS_HEAD);
    } else {
        println!("{}Computer is not vulnerable to MSI installer file esciation.", FAIL_HEAD);
    }
    // Check UAC settings
    println!("{}Checking for UAC bypass...", INFO_HEAD);
    if check_uac_security() == true
    {
        println!("{}Computer is vulnerable to UAC bypass!", PASS_HEAD);
    } else {
        println!("{}Computer is not vulnerable to UAC bypass.", FAIL_HEAD);
    }
    // Check services and loaded DLLs
    println!("{}Checking services for possible DLL hyjacking...", INFO_HEAD);
    let services: Vec<(String, String, String)> = GetServices();
    println!("{}Found {:?} possible services!", PASS_HEAD, services.len());
    let vulnerable_services: Vec<(String, String, String)> = CheckServices(&services);
    if vulnerable_services.len() > 0
    {
        println!("{}Found {:?} vulnerable services!", PASS_HEAD, vulnerable_services.len());
        
    } else {
        println!("{}No vulnerable services found.", FAIL_HEAD);
    }
    // Check common path and folder permissions
    println!("{}Checking known file paths and permissions...", INFO_HEAD);
    let target_paths: Vec<String> = TargetPaths();
    let mut vulnerable_directories: Vec<String> = Vec::default();
    for path in target_paths
    {
        if CanEditDirectory(&path)
        {
            vulnerable_directories.push(path);
        }
    }
    if vulnerable_directories.len() > 0
    {
        println!("{}Found {:?} vulnerable paths! (They REALLY messed up KEK)", PASS_HEAD, vulnerable_directories.len());
    } else {
        println!("{}No vulnerable paths found. (Expected)", FAIL_HEAD);
    }
    // Check PATH variables
    // Check startup items
    // Check scheduled task items
    println!("{}End of program.", IMPT_HEAD);
}