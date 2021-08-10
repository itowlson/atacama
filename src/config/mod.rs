use std::{time::Duration};

use serde::Deserialize;

use crate::trigger::Trigger as ActiveTrigger;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDefinition {
    bindle: String,  // bindle::Id,
    handler: Vec<Handler>,
}

impl AppDefinition {
    pub fn handler(&self) -> Vec<Handler> {
        self.handler.clone()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Handler {
    module_id: String,
    trigger: Trigger,
    binding: Option<Vec<Binding>>
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum Trigger {
    Timer(TimerTriggerConfig),
}

impl Handler {
    pub fn trigger(&self) -> anyhow::Result<Box<dyn ActiveTrigger>> {
        match &self.trigger {
            Trigger::Timer(ttc) => {
                let interval = Duration::from_secs(ttc.interval_in_seconds);
                Ok(Box::new(crate::trigger::TimerTrigger::new(interval)))
            }
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerTriggerConfig {
    interval_in_seconds: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "direction")]
pub enum Binding {
    Output(OutputBinding),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "type")]
pub enum OutputBinding {
    Http(HttpOutputBindingConfig),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HttpOutputBindingConfig {
    method: String,
    url: String,
}
