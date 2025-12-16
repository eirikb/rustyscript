// Copyright 2018-2025 the Deno authors. MIT license.
// Adapted from deno_runtime v0.221.0 inspector_server.rs
// Source: https://github.com/denoland/deno/blob/main/runtime/inspector_server.rs

//! V8 Inspector support for debugging JavaScript/TypeScript code.
//!
//! This module provides a WebSocket server that implements the V8 Inspector Protocol,
//! allowing debuggers like Chrome DevTools, VS Code, and IntelliJ to connect and debug
//! JavaScript/TypeScript code running in the runtime.

use deno_core::futures::channel::mpsc::{unbounded, UnboundedReceiver, UnboundedSender};
use deno_core::futures::StreamExt;
use deno_core::serde_json;
use deno_core::{
    InspectorMsg, InspectorSessionKind, InspectorSessionOptions,
    InspectorSessionProxy, JsRuntimeInspector,
};
use fastwebsockets::{upgrade, Frame, OpCode, Payload};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::thread;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Options for configuring the inspector server.
#[derive(Debug, Clone)]
pub struct InspectorOptions {
    /// The address to bind the inspector server to.
    pub address: SocketAddr,
    /// If true, the runtime will pause execution until a debugger connects.
    pub wait_for_session: bool,
    /// A human-readable name for this inspector session.
    pub name: String,
    /// The URL of the main module being debugged (e.g., file:///path/to/script.ts)
    pub module_url: String,
}

/// Inspector information that is sent from the isolate thread to the server
/// thread when a new inspector is created.
pub struct InspectorInfo {
    pub host: SocketAddr,
    pub uuid: Uuid,
    pub thread_name: Option<String>,
    pub new_session_tx: UnboundedSender<InspectorSessionProxy>,
    pub deregister_rx: deno_core::futures::channel::oneshot::Receiver<()>,
    pub module_url: String,
}

impl InspectorInfo {
    /// Create a new InspectorInfo for the current thread.
    pub fn new(
        host: SocketAddr,
        new_session_tx: &UnboundedSender<InspectorSessionProxy>,
        deregister_rx: deno_core::futures::channel::oneshot::Receiver<()>,
        module_url: String,
    ) -> Self {
        Self {
            host,
            uuid: Uuid::new_v4(),
            thread_name: thread::current().name().map(|n| n.to_string()),
            new_session_tx: new_session_tx.clone(),
            deregister_rx,
            module_url,
        }
    }

    /// Get the WebSocket debugger URL for this inspector.
    pub fn get_websocket_debugger_url(&self) -> String {
        format!("ws://{}:{}/{}", self.host.ip(), self.host.port(), self.uuid)
    }

    /// Get the DevTools frontend URL for this inspector.
    pub fn get_frontend_url(&self) -> String {
        format!(
            "devtools://devtools/bundled/js_app.html?experiments=true&v8only=true&ws={}:{}/{}",
            self.host.ip(),
            self.host.port(),
            self.uuid
        )
    }

    /// Get the title for this inspector session.
    pub fn get_title(&self) -> &str {
        self.thread_name.as_deref().unwrap_or("rustyscript")
    }

    /// Generate JSON metadata for Chrome DevTools discovery.
    pub fn get_json_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "description": "rustyscript",
            "devtoolsFrontendUrl": self.get_frontend_url(),
            "faviconUrl": "https://deno.land/favicon.ico",
            "id": self.uuid.to_string(),
            "title": self.get_title(),
            "type": "node",
            "url": self.module_url,
            "webSocketDebuggerUrl": self.get_websocket_debugger_url(),
        })
    }
}

/// The inspector server that handles WebSocket connections from debuggers.
#[allow(missing_docs)]
pub struct InspectorServer {
    pub host: SocketAddr,
    register_inspector_tx: UnboundedSender<InspectorInfo>,
    shutdown_server_tx: Option<broadcast::Sender<()>>,
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl InspectorServer {
    /// Create a new inspector server bound to the given address.
    pub fn new(address: SocketAddr, name: String) -> Result<Self, std::io::Error> {
        let (register_inspector_tx, register_inspector_rx) = unbounded::<InspectorInfo>();
        let (shutdown_server_tx, shutdown_server_rx) = broadcast::channel::<()>(1);

        let thread_handle = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .enable_time()
                .build()
                .unwrap();

            let local = tokio::task::LocalSet::new();
            local.block_on(&rt, server(address, register_inspector_rx, shutdown_server_rx, name));
        });

        // Give the server a moment to start
        thread::sleep(std::time::Duration::from_millis(50));

        Ok(Self {
            host: address,
            register_inspector_tx,
            shutdown_server_tx: Some(shutdown_server_tx),
            thread_handle: Some(thread_handle),
        })
    }

    /// Register a new inspector with this server.
    pub fn register_inspector(
        &self,
        module_url: String,
        inspector: &Rc<RefCell<JsRuntimeInspector>>,
        wait_for_session: bool,
    ) {
        let new_session_tx = {
            let inspector = inspector.borrow();
            inspector.get_session_sender().clone()
        };

        let deregister_rx = inspector.borrow_mut().add_deregister_handler();

        let info = InspectorInfo::new(self.host, &new_session_tx, deregister_rx, module_url);
        let uuid = info.uuid;

        if self.register_inspector_tx.unbounded_send(info).is_err() {
            log::error!("Failed to register inspector");
        }

        // Print in Node.js-compatible format so IDEs auto-attach
        eprintln!("Debugger listening on ws://{}/{}", self.host, uuid);
        eprintln!("For help, see: https://nodejs.org/en/docs/inspector");

        if wait_for_session {
            // Wait for debugger to connect (but don't break yet - that happens later)
            eprintln!("Waiting for debugger to connect...");
            inspector.borrow_mut().wait_for_session();
            eprintln!("Debugger connected!");
        }
    }
}

/// Wait for debugger session and schedule break on next statement.
/// Call this after setup code (like prep.js) has run, but before user code.
/// This is the --inspect-brk behavior - waits for debugger if not connected,
/// then breaks on the next JavaScript statement.
pub fn wait_for_session_and_break(inspector: &Rc<RefCell<JsRuntimeInspector>>) {
    inspector.borrow_mut().wait_for_session_and_break_on_next_statement();
}

impl Drop for InspectorServer {
    fn drop(&mut self) {
        if let Some(shutdown_tx) = self.shutdown_server_tx.take() {
            let _ = shutdown_tx.send(());
        }
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

async fn server(
    address: SocketAddr,
    mut register_inspector_rx: UnboundedReceiver<InspectorInfo>,
    mut shutdown_rx: broadcast::Receiver<()>,
    _name: String,
) {
    let listener = match TcpListener::bind(address).await {
        Ok(l) => l,
        Err(e) => {
            log::error!("Failed to bind inspector server to {}: {}", address, e);
            return;
        }
    };

    let _bound_addr = listener.local_addr().unwrap();

    let inspectors: Rc<RefCell<HashMap<Uuid, Rc<RefCell<InspectorInfo>>>>> =
        Rc::new(RefCell::new(HashMap::new()));

    // Task to handle inspector registration/deregistration
    let inspectors_clone = inspectors.clone();
    tokio::task::spawn_local(async move {
        while let Some(info) = register_inspector_rx.next().await {
            let uuid = info.uuid;
            let info = Rc::new(RefCell::new(info));
            inspectors_clone.borrow_mut().insert(uuid, info.clone());

            // Spawn task to handle deregistration
            let inspectors_deregister = inspectors_clone.clone();
            tokio::task::spawn_local(async move {
                let deregister_rx = {
                    let mut info = info.borrow_mut();
                    std::mem::replace(
                        &mut info.deregister_rx,
                        deno_core::futures::channel::oneshot::channel().1,
                    )
                };
                let _ = deregister_rx.await;
                inspectors_deregister.borrow_mut().remove(&uuid);
            });
        }
    });

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let inspectors = inspectors.clone();
                        tokio::task::spawn_local(handle_connection(stream, inspectors));
                    }
                    Err(e) => {
                        log::error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                break;
            }
        }
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    inspectors: Rc<RefCell<HashMap<Uuid, Rc<RefCell<InspectorInfo>>>>>,
) {
    let io = TokioIo::new(stream);

    let service = service_fn(|req: Request<Incoming>| {
        let inspectors = inspectors.clone();
        async move { handle_request(req, inspectors).await }
    });

    let conn = http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades();

    if let Err(e) = conn.await {
        if !e.to_string().contains("connection was not a valid HTTP")
            && !e.to_string().contains("early eof")
        {
            log::debug!("Connection error: {}", e);
        }
    }
}

fn handle_json_request(
    inspectors: &Rc<RefCell<HashMap<Uuid, Rc<RefCell<InspectorInfo>>>>>,
) -> Response<http_body_util::Full<Bytes>> {
    let targets: Vec<serde_json::Value> = inspectors
        .borrow()
        .values()
        .map(|info| info.borrow().get_json_metadata())
        .collect();

    let body = serde_json::to_string(&targets).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(Bytes::from(body)))
        .unwrap()
}

fn handle_json_version_request() -> Response<http_body_util::Full<Bytes>> {
    let version = serde_json::json!({
        "Browser": format!("rustyscript/{}", env!("CARGO_PKG_VERSION")),
        "Protocol-Version": "1.3",
        "V8-Version": deno_core::v8::VERSION_STRING,
    });
    let body = serde_json::to_string(&version).unwrap();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(http_body_util::Full::new(Bytes::from(body)))
        .unwrap()
}

fn handle_ws_request(
    req: Request<Incoming>,
    inspectors: &Rc<RefCell<HashMap<Uuid, Rc<RefCell<InspectorInfo>>>>>,
) -> Option<Response<http_body_util::Full<Bytes>>> {
    let path = req.uri().path();

    // Accept both /{uuid} (Node.js style) and /ws/{uuid}
    let uuid_str = if path.starts_with("/ws/") {
        Some(&path[4..])
    } else if path.len() > 1 && !path.starts_with("/json") {
        Some(&path[1..])
    } else {
        None
    };

    let uuid_str = uuid_str?;
    let uuid = Uuid::parse_str(uuid_str).ok()?;

    // run in a block to not hold borrow to `inspectors` for too long
    let info = {
        inspectors.borrow().get(&uuid).cloned()
    }?;

    if !fastwebsockets::upgrade::is_upgrade_request(&req) {
        return None;
    }

    let (response, fut) = upgrade::upgrade(req).unwrap();

    // spawn a task that will wait for websocket connection and then pump messages between
    // the socket and inspector proxy
    tokio::task::spawn_local(async move {
        match fut.await {
            Ok(ws) => {
                pump_websocket_messages(ws, info).await;
            }
            Err(e) => {
                log::error!("WebSocket upgrade failed: {:?}", e);
            }
        }
    });

    let (parts, _) = response.into_parts();
    Some(Response::from_parts(parts, http_body_util::Full::new(Bytes::new())))
}

async fn handle_request(
    req: Request<Incoming>,
    inspectors: Rc<RefCell<HashMap<Uuid, Rc<RefCell<InspectorInfo>>>>>,
) -> Result<Response<http_body_util::Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    if path == "/json" || path == "/json/list" {
        return Ok(handle_json_request(&inspectors));
    }

    if path == "/json/version" {
        return Ok(handle_json_version_request());
    }

    if let Some(response) = handle_ws_request(req, &inspectors) {
        return Ok(response);
    }

    log::debug!("Inspector: 404 for path: {}", path);
    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(http_body_util::Full::new(Bytes::from("Not Found")))
        .unwrap())
}

/// The pump future takes care of forwarding messages between the websocket
/// and channels. It resolves when either side disconnects, ignoring any
/// errors.
///
/// The future proxies messages sent and received on a WebSocket
/// to a UnboundedSender/UnboundedReceiver pair. We need these "unbounded" channel ends to sidestep
/// Tokio's task budget, which causes issues when JsRuntimeInspector::poll_sessions()
/// needs to block the thread because JavaScript execution is paused.
///
/// This works because UnboundedSender/UnboundedReceiver are implemented in the
/// 'futures' crate, therefore they can't participate in Tokio's cooperative
/// task yielding.
async fn pump_websocket_messages(
    ws: fastwebsockets::WebSocket<TokioIo<hyper::upgrade::Upgraded>>,
    info: Rc<RefCell<InspectorInfo>>,
) {
    log::debug!("WebSocket connection established");

    // The 'outbound' channel carries messages sent to the websocket.
    // The 'inbound' channel carries messages received from the websocket.
    let (inbound_tx, inbound_rx) = unbounded::<String>();
    let (outbound_tx, mut outbound_rx) = unbounded::<InspectorMsg>();

    let proxy = InspectorSessionProxy {
        tx: outbound_tx,
        rx: inbound_rx,
        options: InspectorSessionOptions {
            kind: InspectorSessionKind::Blocking,
        },
    };

    // Send the proxy to the inspector
    {
        let info = info.borrow();
        if info.new_session_tx.unbounded_send(proxy).is_err() {
            log::error!("Failed to send inspector session proxy");
            return;
        }
    }

    // Split the WebSocket into independent read and write halves.
    // This avoids the deadlock where read blocks write.
    let (ws_read, mut ws_write) = ws.split(|stream| tokio::io::split(stream));
    let mut ws_read = fastwebsockets::FragmentCollectorRead::new(ws_read);

    // Task to forward messages from WebSocket to inspector (inbound)
    let read_task = async move {
        loop {
            match ws_read.read_frame(&mut |_| async { Ok::<_, std::io::Error>(()) }).await {
                Ok(frame) => {
                    match frame.opcode {
                        OpCode::Text | OpCode::Binary => {
                            let msg = String::from_utf8_lossy(&frame.payload).to_string();
                            log::trace!("<- DevTools: {}", &msg[..std::cmp::min(200, msg.len())]);
                            if inbound_tx.unbounded_send(msg).is_err() {
                                // Users don't care if there was an error coming from debugger,
                                // just about the fact that debugger did disconnect.
                                log::debug!("Inspector channel closed");
                                break;
                            }
                        }
                        OpCode::Close => {
                            log::debug!("WebSocket closed by client");
                            break;
                        }
                        // Ignore other messages.
                        _ => {}
                    }
                }
                Err(e) => {
                    log::debug!("WebSocket read error: {:?}", e);
                    break;
                }
            }
        }
    };

    // Task to forward messages from inspector to WebSocket (outbound)
    let write_task = async move {
        loop {
            match outbound_rx.next().await {
                Some(msg) => {
                    log::trace!("-> DevTools: {}", &msg.content[..std::cmp::min(200, msg.content.len())]);
                    let frame = Frame::text(Payload::Borrowed(msg.content.as_bytes()));
                    if let Err(e) = ws_write.write_frame(frame).await {
                        log::debug!("WebSocket write error: {:?}", e);
                        break;
                    }
                }
                None => {
                    log::debug!("V8 channel closed");
                    break;
                }
            }
        }
    };

    tokio::select! {
        _ = read_task => {}
        _ = write_task => {}
    }
}
