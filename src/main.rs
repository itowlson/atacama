use clap::{App, Arg};

use crate::config::AppDefinition;

mod config;

const ABOUT: &str = r#"
Run an event handling provcess
"#;

// const BINDLE_URL: &str = "BINDLE_URL";
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
        .get_matches();

    let config_path = matches.value_of(ARG_CONFIG_FILE).unwrap();
    let data = std::fs::read(config_path).map_err(|e| anyhow::anyhow!("Can't read config file {}: {}", config_path, e))?;
    let app: AppDefinition = toml::from_slice(&data)?;

    println!("{:?}", &app);

    Ok(())
}
