/* This file will have the code to parse and understand the config file for flashbang
*
* The main config for flashbang will be in a file called flashbang.yaml and placed in the home config directory
*/

use crate::rules::{ColorFunctionMap, Rule};
use dirs::config_dir;
use std::path::PathBuf;
use std::sync::LazyLock;

static CONFIG_DIR: LazyLock<PathBuf> = LazyLock::new(|| {
    let directory = config_dir()
        .expect("Could not find config directory")
        .join("flashbang");
    std::fs::create_dir_all(&directory).expect("Could not create flashbang config directory");

    let path = directory.join("flashbang.yaml");

    if !path.exists() {
        std::fs::write(&path, include_str!("../config.yaml"))
            .expect("Failed to create default config.yaml");
    }

    println!("Using {} for config directory\n", path.display());
    path
});

pub fn load_rules() -> Vec<Rule> {
    // read from config dir
    let file = std::fs::File::open(&*CONFIG_DIR).expect("Could not open config file");
    let config: yaml_serde::Value =
        yaml_serde::from_reader(file).expect("Could not parse config yaml");

    let mut rules: Vec<Rule> = Vec::new();

    let apps = config["applications"]
        .as_sequence()
        .expect("Expected applications in config");

    println!("Applications: {:?}", apps);

    for app in apps {
        println!("Name: {:?} - function: {:?}", app["name"], app["function"]);
        let action = ColorFunctionMap
            .get(app["function"].as_str().expect("Function cannot be null"))
            .expect("Unknown color function")
            .clone();

        rules.push(
            Rule::new(
                app["name"].as_str().expect("Name cannot be null"),
                app["regex"].as_str().expect("Regex cannot be null"),
                action,
            )
            .expect("Invalid rule regex"),
        );
    }

    rules
}

pub fn load_devices() -> Vec<String> {
    let file = std::fs::File::open(&*CONFIG_DIR).expect("Could not open config file");
    let mut loaded_devices: Vec<String> = vec![];

    let config: yaml_serde::Value =
        yaml_serde::from_reader(file).expect("Could not parse config yaml");

    for device in config["devices"]
        .as_sequence()
        .expect("Devices must be a list")
    {
        loaded_devices.push(
            device["name"]
                .as_str()
                .expect("Device name must be a string")
                .to_string(),
        );
    }

    loaded_devices
}

// Not really sure how this is going to work, store a map from text -> function? how do we compile this on the fly
pub fn load_functions() {
    // idek what im going to do here yet
}
