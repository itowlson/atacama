//! The tools for executing WAGI modules

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::{collections::HashMap, net::SocketAddr};
use std::{
    hash::{Hash, Hasher},
    io::BufRead,
};

use cap_std::fs::Dir;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, instrument};
use url::Url;
use wasi_cap_std_sync::WasiCtxBuilder;
use wasi_common::pipe::{ReadPipe, WritePipe};
use wasmtime::*;
use wasmtime_wasi::*;

// use crate::version::*;
use crate::{/* http_util::*,*/ runtime::bindle::bindle_cache_key};

pub mod bindle;

/// The default Bindle server URL.
pub const DEFAULT_BINDLE_SERVER: &str = "http://localhost:8080/v1";

const WASM_LAYER_CONTENT_TYPE: &str = "application/vnd.wasm.content.layer.v1+wasm";
const STDERR_FILE: &str = "module.stderr";

type EventData = String;

fn internal_error<T>(text: &str) -> anyhow::Result<T> {
    Err(anyhow::anyhow!("Internal error: {}", text))
}

/// An internal representation of a mapping from a URI fragment to a function in a module.
#[derive(Clone)]
pub struct RouteEntry {
    pub path: String,
    pub entrypoint: String,
}

/// A handler contains all of the information necessary to execute the correct function on a module.
#[derive(Clone, Debug)]
pub struct Handler {
    /// A reference to the module for this handler.
    pub module: Module,
    /// The function that should be called to handle this path.
    pub entrypoint: String,
    /// The path pattern that this handler answers.
    ///
    // For example, an exact path `/foo/bar` may be returned, as may a wildcard path such as `/foo/...`
    //
    // This path is the _fully constructed_ path. That is, if a module config declares its path as `/base`,
    // and the module registers the path `/foo/...`, the value of this would be `/base/foo/...`.
    pub path: String,
}

impl Handler {
    /// Given a module and a route entry, create a new handler.
    pub fn new(entry: RouteEntry, module: Module) -> Self {
        Handler {
            path: entry.path,
            entrypoint: entry.entrypoint,
            module,
        }
    }
}

/// Description of a single WAGI module
#[derive(Clone, Debug, Deserialize)]
pub struct Module {
    pub key: Option<String>,
    /// The path to the module that will be loaded.
    ///
    /// This should be an absolute path. It must point to a WASM+WASI 32-bit program
    /// with the read bit set.
    pub module: String,
    // /// Directories on the local filesystem that can be opened by this module
    // /// The key (left value) is the name of the directory INSIDE the WASM. The value is
    // /// the location OUTSIDE the WASM. Two inside locations can map to the same outside
    // /// location.
    // pub volumes: Option<HashMap<String, String>>,
    // /// The name of the function that is the entrypoint for executing the module.
    // /// The default is `_start`.
    // pub entrypoint: Option<String>,
    // /// The URL fragment for the bindle server.
    // ///
    // /// If none is supplied, then http://localhost:8080/v1 is used
    pub bindle_server: Option<String>,

    // /// List of hosts that the guest module is allowed to make HTTP requests to.
    // /// If none or an empty vector is supplied, the guest module cannot send
    // /// requests to any server.
    // pub allowed_hosts: Option<Vec<String>>,
}

// For hashing, we don't need all of the fields to hash. A wasm module (not a `Module`) can be used
// multiple times and configured different ways, but the route can only be used once per WAGI
// instance
impl Hash for Module {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.hash(state);
    }
}

impl PartialEq for Module {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}

impl Eq for Module {}

impl Module {
    pub fn new(key: String, module_uri: String) -> Self {
        Module {
            key: Some(key),
            module: module_uri,
            bindle_server: None,
        }
    }

    /// Execute the WASM module in a WAGI
    ///
    /// The given `base_log_dir` should be a directory where all module logs will be stored. When
    /// executing a module, a subdirectory will be created in this directory with the ID (from the
    /// [`id` method](Module::id)) for its name. The log will be placed in that directory at
    /// `module.stderr`
    #[allow(clippy::too_many_arguments)]
    //#[instrument(level = "trace", skip(self, entrypoint, req, client_addr, cache_config_path, module_cache_dir, base_log_dir, default_host), fields(route = %self.route, module = %self.module))]
    pub async fn execute(
        &self,
        entrypoint: &str,
        event_data: EventData,
        client_addr: SocketAddr,
        cache_config_path: &Path,
        module_cache_dir: &Path,
        base_log_dir: &Path,
        default_host: String,
        env_vars: HashMap<String, String>,
    ) -> anyhow::Result<Vec<u8>> {
        let data = event_data.as_bytes()
            .to_vec();
        let ep = entrypoint.to_owned();
        let me = self.clone();
        // Get owned copies of the various paths to pass into the thread
        let cccp = cache_config_path.to_owned();
        let mcd = module_cache_dir.to_owned();
        let bld = base_log_dir.to_owned();
        let res = match tokio::task::spawn_blocking(move || {
            me.run_wasm(
                &ep,
                &event_data,
                data,
                client_addr,
                &cccp,
                &mcd,
                &bld,
                default_host.as_str(),
                env_vars,
            )
        })
        .await
        {
            Ok(res) => res,
            Err(e) if e.is_panic() => {
                tracing::error!(error = %e, "Recoverable panic on Wasm Runner thread");
                return internal_error("Module run error");
            }
            Err(e) => {
                tracing::error!(error = %e, "Recoverable panic on Wasm Runner thread");
                return internal_error("module run was cancelled");
            }
        };

        res
    }

    /// Returns the unique ID of the module.
    ///
    /// This is the SHA256 sum of the following data, written into the hasher in the following order
    /// (skipping any `None`s):
    ///
    /// - route
    /// - host
    pub fn id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.route);
        format!("{:x}", hasher.finalize())
    }

    /// Examine the given module to see if it has any routes.
    ///
    /// If it has any routes, add them to the vector and return it. The given `base_log_dir` should
    /// be a directory where all module logs will be stored. When executing a module, a subdirectory
    /// will be created in this directory with the ID (from the [`id` method](Module::id)) for its
    /// name. The log will be placed in that directory at `module.stderr`
    #[instrument(
        level = "trace",
        skip(self, cache_config_path, module_cache_dir, base_log_dir)
    )]
    pub(crate) fn load_routes(
        &self,
        cache_config_path: &Path,
        module_cache_dir: &Path,
        base_log_dir: &Path,
    ) -> Result<Vec<RouteEntry>, anyhow::Error> {
        let startup_span = tracing::info_span!("route_instantiation").entered();

        let prefix = self
            .route
            .strip_suffix("/...")
            .unwrap_or_else(|| self.route.as_str());
        let mut routes = vec![RouteEntry {
            path: self.route.to_owned(), // We don't use prefix because prefix has been normalized.
            entrypoint: self
                .entrypoint
                .clone()
                .unwrap_or_else(|| "_start".to_string()),
        }];

        // TODO: We should dedup this code somewhere because there are plenty of similarities to
        // `run_wasm`

        // Make sure the directory exists
        let log_dir = base_log_dir.join(self.id());
        std::fs::create_dir_all(&log_dir)?;
        // Open a file for appending. Right now this will just keep appending as there is no log
        // rotation or cleanup
        let stderr = unsafe {
            cap_std::fs::File::from_std(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(log_dir.join(STDERR_FILE))?,
            )
        };
        let stderr = wasi_cap_std_sync::file::File::from_cap_std(stderr);

        let stdout_buf: Vec<u8> = vec![];
        let stdout_mutex = Arc::new(RwLock::new(stdout_buf));
        let stdout = WritePipe::from_shared(stdout_mutex.clone());

        let ctx = WasiCtxBuilder::new()
            .stderr(Box::new(stderr))
            .stdout(Box::new(stdout))
            .build();

        let (mut store, engine) = self.new_store_and_engine(cache_config_path, ctx)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)?;

        let http = wasi_experimental_http_wasmtime::HttpCtx::new(None, None)?;
        http.add_to_linker(&mut linker)?;

        let module = self.load_cached_module(&store, module_cache_dir)?;
        let instance = linker.instantiate(&mut store, &module)?;

        // Manually drop the span to get the instantiation time
        drop(startup_span);

        match instance.get_func(&mut store, "_routes") {
            Some(func) => {
                func.call(&mut store, &[])?;
            }
            None => return Ok(routes),
        }

        let out = stdout_mutex.read().unwrap();
        out.lines().for_each(|line_result| {
            if let Ok(line) = line_result {
                // Split line into parts
                let parts: Vec<&str> = line.trim().split_whitespace().collect();

                if parts.is_empty() {
                    return;
                }

                let key = parts.get(0).unwrap_or(&"/").to_string();
                let val = parts.get(1).unwrap_or(&"_start").to_string();
                routes.push(RouteEntry {
                    path: format!("{}{}", prefix, key),
                    entrypoint: val,
                });
            }
        });
        // We reverse the routes so that the top-level routes are evaluated last.
        // This gives a predictable order for traversing routes. Because the base path
        // is the last one evaluated, if the base path is /..., it will match when no
        // other more specific route lasts.
        //
        // Additionally, when Wasm authors create their _routes() callback, they can
        // organize their outputs to match according to their own precedence merely by
        // putting the higher precedence routes at the end of the output.
        routes.reverse();
        Ok(routes)
    }

    // Load and execute the WASM module.
    //
    // Typically, the higher-level execute() method should be used instead, as that handles
    // wrapping errors in the appropriate HTTP response. This is a lower-level function
    // that returns the errors that occur during processing of a WASM module.
    //
    // Note that on occasion, this module COULD return an Ok() with a response body that
    // contains an HTTP error. This can occur, for example, if the WASM module sets
    // the status code on its own.
    //
    // TODO: Waaaay too many args
    #[allow(clippy::too_many_arguments)]
    // #[instrument(level = "info", skip(self, req, body, client_addr, cache_config_path, cache_dir, base_log_dir, default_host), fields(uri = %req.uri, module = %self.module))]
    fn run_wasm(
        &self,
        entrypoint: &str,
        event_data: &EventData,
        data: Vec<u8>,
        client_addr: SocketAddr,
        cache_config_path: &Path,
        cache_dir: &Path,
        base_log_dir: &Path,
        default_host: &str,
        env: HashMap<String, String>,
    ) -> Result<Vec<u8>, anyhow::Error> {
        let startup_span = tracing::info_span!("module instantiation").entered();
        let stdin = ReadPipe::from(data);
        let stdout_buf: Vec<u8> = vec![];
        let stdout_mutex = Arc::new(RwLock::new(stdout_buf));
        let stdout = WritePipe::from_shared(stdout_mutex.clone());

        // Make sure the directory exists
        let log_dir = base_log_dir.join(self.id());
        tracing::info!(log_dir = %log_dir.display(), "Using log dir");
        std::fs::create_dir_all(&log_dir)?;
        // Open a file for appending. Right now this will just keep appending as there is no log
        // rotation or cleanup
        let stderr = unsafe {
            cap_std::fs::File::from_std(
                std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(log_dir.join(STDERR_FILE))?,
            )
        };
        let stderr = wasi_cap_std_sync::file::File::from_cap_std(stderr);
        // The spec does not say what to do with STDERR.
        // See specifically sections 4.2 and 6.1 of RFC 3875.
        // Currently, we will attach to wherever logs go.

        let mut builder = WasiCtxBuilder::new()
            // .args(&args)?
            // .envs(&headers)?
            .stderr(Box::new(stderr)) // STDERR goes to the console of the server
            .stdout(Box::new(stdout)) // STDOUT is sent to a Vec<u8>, which becomes the Body later
            .stdin(Box::new(stdin));

        // // Map all of the volumes.
        // if let Some(dirs) = self.volumes.as_ref() {
        //     for (guest, host) in dirs.iter() {
        //         debug!(%host, %guest, "Mapping volume from host to guest");
        //         // Try to open the dir or log an error.
        //         match unsafe { Dir::open_ambient_dir(host) } {
        //             Ok(dir) => {
        //                 builder = builder.preopened_dir(dir, guest)?;
        //             }
        //             Err(e) => tracing::error!(%host, %guest, error = %e, "Error opening directory"),
        //         };
        //     }
        // }

        let ctx = builder.build();

        let (mut store, engine) = self.new_store_and_engine(cache_config_path, ctx)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::add_to_linker(&mut linker, |cx| cx)?;

        let http = wasi_experimental_http_wasmtime::HttpCtx::new(self.allowed_hosts.clone(), None)?;
        http.add_to_linker(&mut linker)?;

        let module = self.load_cached_module(&store, cache_dir)?;
        let instance = linker.instantiate(&mut store, &module)?;

        // Manually drop the span so we get instantiation time
        drop(startup_span);

        // This shouldn't error out, because we already know there is a match.
        let start = instance.get_func(&mut store, entrypoint).ok_or_else(|| {
            anyhow::anyhow!("No such function '{}' in {}", entrypoint, self.module)
        })?;

        tracing::trace!("Calling Wasm entry point");
        start.call(&mut store, &[])?;

        // Okay, once we get here, all the information we need to send back in the response
        // should be written to the STDOUT buffer. We fetch that, format it, and send
        // it back. In the process, we might need to alter the status code of the result.
        //
        // This is a little janky, but basically we are looping through the output once,
        // looking for the double-newline that distinguishes the headers from the body.
        // The headers can then be parsed separately, while the body can be sent back
        // to the client.
        let out = stdout_mutex.read().unwrap();
        let mut last = 0;
        let mut scan_headers = true;
        let mut buffer: Vec<u8> = Vec::new();
        let mut out_headers: Vec<u8> = Vec::new();
        out.iter().for_each(|i| {
            if scan_headers && *i == 10 && last == 10 {
                out_headers.append(&mut buffer);
                buffer = Vec::new();
                scan_headers = false;
                return; // Consume the linefeed
            }
            last = *i;
            buffer.push(*i)
        });

        Ok(buffer)
    }

    /// Determine the source of the module, and read it from that source.
    ///
    /// Modules can be stored locally, or they can be stored in external sources like
    /// Bindle. WAGI determines the source by looking at the URI of the module.
    ///
    /// - If `file:` is specified, or no schema is specified, this loads from the local filesystem
    /// - If `bindle:` is specified, this will retrieve the module from the configured Bindle server
    /// - If `oci:` is specified, this will retrieve the module from an OCI Distribution registry
    ///
    /// While `file` is a little lenient in its adherence to the URL spec, `bindle` and `oci` are not.
    /// For example, an `oci` URL that references `alpine:latest` should be `oci:alpine:latest`.
    /// It should NOT be `oci://alpine:latest` because `alpine` is not a host name.
    async fn load_module(
        &self,
        store: &Store<WasiCtx>,
        cache: &Path,
    ) -> anyhow::Result<wasmtime::Module> {
        tracing::trace!(
            module = %self.module,
            "Loading from source"
        );
        match Url::parse(self.module.as_str()) {
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "Error parsing module URI. Assuming this is a local file"
                );
                wasmtime::Module::from_file(store.engine(), self.module.as_str())
            }
            Ok(uri) => match uri.scheme() {
                "file" => {
                    match uri.to_file_path() {
                        Ok(p) => return wasmtime::Module::from_file(store.engine(), p),
                        Err(e) => anyhow::bail!("Cannot get path to file: {:#?}", e),
                    };
                }
                "bindle" => self.load_bindle(&uri, store.engine(), cache).await,
                s => anyhow::bail!("Unknown scheme {}", s),
            },
        }
    }

    /// Load a cached module from the filesystem.
    ///
    /// This is synchronous right now because Wasmtime on the runner needs to be run synchronously.
    /// This will change when the new version of Wasmtime adds Send + Sync to all the things.
    /// Then we can just do `load_module` or refactor this to be async.
    #[instrument(level = "info", skip(self, store, cache_dir), fields(cache = %cache_dir.display(), module = %self.module))]
    fn load_cached_module(
        &self,
        store: &Store<WasiCtx>,
        cache_dir: &Path,
    ) -> anyhow::Result<wasmtime::Module> {
        let canonical_path = match Url::parse(self.module.as_str()) {
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "Error parsing module URI. Assuming this is a local file."
                );
                PathBuf::from(self.module.as_str())
            }
            Ok(uri) => match uri.scheme() {
                "file" => match uri.to_file_path() {
                    Ok(p) => p,
                    Err(e) => anyhow::bail!("Cannot get path to file: {:#?}", e),
                },
                "bindle" => cache_dir.join(bindle_cache_key(&uri)),
                "parcel" => {
                    // parcel: bindle_uri#SHA256 becomes cache_dir/SHA256
                    let cache_file = uri.fragment().unwrap_or_else(|| uri.path()); // should always have fragment
                    cache_dir.join(cache_file)
                }
                "oci" => cache_dir.join(self.hash_name()),
                s => {
                    tracing::error!(scheme = s, "unknown scheme in module");
                    anyhow::bail!("Unknown scheme {}", s)
                }
            },
        };
        tracing::trace!(?canonical_path);

        // If there is a module at this path, load it.
        // Right now, _any_ problem loading the module will result in us trying to
        // re-fetch it.
        match wasmtime::Module::from_file(store.engine(), canonical_path) {
            Ok(module) => Ok(module),
            Err(_e) => {
                tracing::debug!("module cache miss. Loading module from remote.");
                // TODO: This could be reallllllllly dangerous as we are for sure going to block at this
                // point on this current thread. This _should_ be ok given that we run this as a
                // spawn_blocking, but those sound like famous last words waiting to happen. Refactor this
                // sooner rather than later
                futures::executor::block_on(self.load_module(&store, cache_dir))
            }
        }
    }

    fn hash_name(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.module.as_str());
        let result = hasher.finalize();
        format!("{:x}", result)
    }

    #[instrument(level = "info", skip(self, engine, cache), fields(server = ?self.bindle_server))]
    async fn load_bindle(
        &self,
        uri: &Url,
        engine: &Engine,
        cache: &Path,
    ) -> anyhow::Result<wasmtime::Module> {
        bindle::load_bindle(
            self.bindle_server
                .clone()
                .unwrap_or_else(|| DEFAULT_BINDLE_SERVER.to_owned())
                .as_str(),
            uri,
            engine,
            cache,
        )
        .await
    }

    // #[instrument(level = "info", skip(self, engine, cache))]
    // async fn load_parcel(
    //     &self,
    //     uri: &Url,
    //     engine: &Engine,
    //     cache: &Path,
    // ) -> anyhow::Result<wasmtime::Module> {
    //     let bs = self
    //         .bindle_server
    //         .clone()
    //         .unwrap_or_else(|| DEFAULT_BINDLE_SERVER.to_owned());
    //     bindle::load_parcel(bs.as_str(), uri, engine, cache).await
    // }

    fn new_store_and_engine(
        &self,
        cache_config_path: &Path,
        ctx: WasiCtx,
    ) -> Result<(Store<WasiCtx>, Engine), anyhow::Error> {
        let mut config = Config::default();
        if let Ok(p) = std::fs::canonicalize(cache_config_path) {
            config.cache_config_load(p)?;
        };

        let engine = Engine::new(&config)?;
        Ok((Store::new(&engine, ctx), engine))
    }
}
