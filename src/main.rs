use openrgb2::{Controller, OpenRgbClient};

mod rules;
use rules::*;

mod anchor;
use anchor::AnchorClient;

mod config;
use config::*;

fn print_all_configs(controllers: &Vec<&Controller>) {
    println!("Printing configs");
    for controller in controllers {
        println!(
            "{}: mode={}",
            controller.name(),
            controller.active_mode().name()
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const IDLE_PROFILE: &str = "flashbang-idle";

    if std::env::args().any(|argument| argument == "--check-anchor") {
        let _anchor = AnchorClient::connect().await?;
        println!("Anchor connection and notification subscription succeeded");
        return Ok(());
    }

    let devices = load_devices();

    let client = OpenRgbClient::connect().await?;
    let controllers = client.get_all_controllers().await?;

    // Selecting by name is safer than assuming controller index 0.
    let controllers: Vec<_> = controllers
        .iter()
        .filter(|controller| devices.iter().any(|device| device == controller.name()))
        .collect();

    print_all_configs(&controllers);

    // Capture the current colors and modes before the animation changes them.
    client.save_profile(IDLE_PROFILE).await?;

    let rules: Vec<Rule> = load_rules();
    println!("Loaded {} rules", rules.len());

    // Anchor client for notifications
    let anchor = AnchorClient::connect().await?;

    // Main rule engine loop
    loop {
        let notification = anchor.next_notification().await?;
        let content = format!(
            "{}\n{}\n{}\n{}",
            notification.application_id,
            notification.application_name,
            notification.title,
            notification.body,
        );

        println!(
            "Notification from {}: {} — {}",
            notification.application_name, notification.title, notification.body
        );

        if let Some(rule) = rules.iter().find(|rule| rule.matches(&content)) {
            rule.run(&controllers).await;
            client.load_profile(IDLE_PROFILE).await?; // load back idle config when done
            print_all_configs(&controllers);
        }
    }
}
