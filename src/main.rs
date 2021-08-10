use clap::{App, Arg};
use calloop::{EventLoop, LoopSignal};

use crate::config::AppDefinition;

mod config;
mod runtime;
mod trigger;

const ABOUT: &str = r#"
Run an event handling provcess
"#;

const ARG_BINDLE_URL: &str = "BINDLE_URL";
const ARG_CONFIG_FILE: &str = "CONFIG_FILE";

#[tokio::main]
pub async fn main() -> Result<(), anyhow::Error> {
    // tracing_subscriber::fmt()
    //     .with_writer(std::io::stderr)
    //     .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
    //     .init();
    let matches = App::new("WAGI Server")
        .version(clap::crate_version!())
        .author("DeisLabs")
        .about(ABOUT)
        .arg(
            Arg::with_name(ARG_CONFIG_FILE)
                .short("c")
                .long("config")
                .value_name("CONFIG_FILE")
                .help("the path to the atacama.toml configuration file")
                .takes_value(true)
                .default_value("./atacama.toml"),
        )
        .arg(
            Arg::with_name(ARG_BINDLE_URL)
                .long("bindle-url")
                .value_name("BINDLE_URL")
                .env("BINDLE_URL")
                .help("The Bindle server URL, e.g. https://example.com:8080/v1. Note that the version path (v1) is required.")
                .takes_value(true)
                .default_value("http://localhost:8080/v1"),
        )
        .get_matches();

    let config_path = matches.value_of(ARG_CONFIG_FILE).unwrap();
    let bindle_url = matches.value_of(ARG_CONFIG_FILE).unwrap();

    let data = std::fs::read(config_path).map_err(|e| anyhow::anyhow!("Can't read config file {}: {}", config_path, e))?;
    let app: AppDefinition = toml::from_slice(&data)?;

    println!("{:?}", bindle_url);
    println!("{:?}", &app);

    let mut event_loop: EventLoop<LoopSignal> = EventLoop::try_new()?;
    let loop_handle = event_loop.handle();
    let mut loop_signal = event_loop.get_signal();

    for handler in &app.handler() {
        // TODO: this does not hook up any kind of callback
        handler.trigger()?.provide_events(&loop_handle)?;
    }

    event_loop
        .run(
            std::time::Duration::from_millis(20),
            &mut loop_signal,
            |_loop_signal| {},
        )?;

    Ok(())
}
