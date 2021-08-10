use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDefinition {
    bindle: String,  // bindle::Id,
    handler: Vec<Handler>,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TimerTriggerConfig {
    interval: String,
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
