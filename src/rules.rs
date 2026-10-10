use openrgb2::{Color, Controller, OpenRgbResult};
use regex::Regex;
use std::sync::LazyLock;
use std::{collections::HashMap, time::Duration};

pub static ColorFunctionMap: LazyLock<HashMap<String, ColorFunction>> = LazyLock::new(|| {
    let mut hashmap: HashMap<String, ColorFunction> = HashMap::new();
    hashmap.insert("blink_red".to_string(), ColorFunction::BlinkRed);
    hashmap
});

// for the effects that are used
#[derive(Clone)]
enum Effect {
    RestoreProfile,
    SetColor([u8; 3]),
    Wait { duration_ms: u64 },
}

/// The built-in effect to run when a rule matches.
#[derive(Clone)]
pub enum ColorFunction {
    BlinkRed,
    FlashRed,
    CustomFunc(Vec<Effect>), // takes a vector of effects that you can use to compose your own rules
}

pub struct Rule {
    pub regex: Regex,
    pub action: ColorFunction,
    pub name: String,
}

impl Rule {
    pub fn new(name: &str, regex: &str, action: ColorFunction) -> Result<Self, regex::Error> {
        Ok(Self {
            name: name.to_string(),
            regex: Regex::new(regex)?,
            action,
        })
    }

    pub fn matches(&self, text: &str) -> bool {
        self.regex.is_match(text)
    }

    pub async fn run(&self, controllers: &[&Controller]) {

        match self.action {
            // This is the main engine for running all of the rules
            ColorFunction::BlinkRed => blink_red(controllers).await,
            _ => println!("Case not handled for running rule\n"),
        }
    }
}

fn lerp(start: f32, end: f32, amount: f32) -> f32 {
    start + (end - start) * amount
}

async fn set_all_leds(controllers: &[&Controller], color: Color) -> OpenRgbResult<()> {
    for controller in controllers {
        controller.set_all_leds(color).await?;
    }
    Ok(())
}

/// Run the effect for a matching Discord notification.
async fn blink_red(controllers: &[&Controller]) {
    for controller in controllers {
        controller.set_controllable_mode().await;
    }

    let keypoints = [
        Color::new(0, 0, 0),
        Color::new(10, 0, 0),
        Color::new(200, 0, 0),
        Color::new(0, 0, 0),
    ];

    for pair in keypoints.windows(2) {
        let start = pair[0];
        let end = pair[1];

        let step = 3;
        for step in 1..=10 {
            let amount = step as f32 / 10.0;
            let color = Color::new(
                lerp(start.r as f32, end.r as f32, amount).round() as u8,
                lerp(start.g as f32, end.g as f32, amount).round() as u8,
                lerp(start.b as f32, end.b as f32, amount).round() as u8,
            );
            let _ = set_all_leds(controllers, color).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
