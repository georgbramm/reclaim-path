extern crate rust_se;

use std::time::{Duration, Instant};
use actix::prelude::*;
use actix_files as fs;
use actix_web::{guard, middleware, web, App, Error, HttpRequest, HttpResponse, HttpServer};
use actix_web_actors::ws;
use actix_web::http::{header, Method, StatusCode};
use serde::{Deserialize, Serialize};
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use std::io;
/// How often heartbeat pings are sent
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
/// How long before lack of client response causes a timeout
const CLIENT_TIMEOUT: Duration = Duration::from_secs(15);

const HTML_FOLDER: &'static str = "static/html/";
const JS_FOLDER: &'static str = "static/js/";
const CSS_FOLDER: &'static str = "static/css/";
const IMG_FOLDER: &'static str = "static/img/";
const FILE_INDEX: &'static str = "index.html";
const FILE_MAP: &'static str = "map.html";
const FILE_NOTFOUND: &'static str = "404.html";
const FILE_ICON: &'static str = "favicon.ico";

/// favicon handler
async fn favicon() -> Result<fs::NamedFile, Error> {
    Ok(fs::NamedFile::open([IMG_FOLDER, FILE_ICON].concat())?)
}

/// 404 handler
async fn p404() -> Result<fs::NamedFile, Error> {
    Ok(fs::NamedFile::open([HTML_FOLDER, FILE_NOTFOUND].concat())?.set_status_code(StatusCode::NOT_FOUND))
}

/// handler with path parameters like `/user/{name}/`
async fn map_param(req: HttpRequest, path: web::Path<(String,)>) -> HttpResponse {
    println!("{:?}", req);
    HttpResponse::Ok()
        .content_type("text/plain")
        .body(format!("map {}!", path.0))
}

/// do websocket handshake and start `MyWebSocket` actor
async fn ws_index(r: HttpRequest, stream: web::Payload) -> Result<HttpResponse, Error> {
    println!("{:?}", r);
    let res = ws::start(MyWebSocket::new(), &r, stream);
    println!("{:?}", res);
    res
}

/// websocket connection is long running connection, it easier
/// to handle with an actor
struct MyWebSocket {
    /// Client must send ping at least once per 10 seconds (CLIENT_TIMEOUT),
    /// otherwise we drop connection.
    hb: Instant,
}

impl Actor for MyWebSocket {
    type Context = ws::WebsocketContext<Self>;

    /// Method is called on actor start. We start the heartbeat process here.
    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
    }
}

/// Handler for `ws::Message`
impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for MyWebSocket {
    fn handle(
        &mut self,
        msg: Result<ws::Message, ws::ProtocolError>,
        ctx: &mut Self::Context,
    ) {
        // process websocket messages
        println!("WS: {:?}", msg);
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(text)) => ctx.text(text),
            Ok(ws::Message::Binary(bin)) => ctx.binary(bin),
            Ok(ws::Message::Close(_)) => {
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

impl MyWebSocket {
    fn new() -> Self {
        Self { hb: Instant::now() }
    }

    /// helper method that sends ping to client every second.
    ///
    /// also this method checks heartbeats from client
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            // check client heartbeats
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                // heartbeat timed out
                println!("Websocket Client heartbeat failed, disconnecting!");

                // stop actor
                ctx.stop();

                // don't try to send a ping
                return;
            }

            ctx.ping(b"");
        });
    }
}

#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "actix_server=info,actix_web=info");
    env_logger::init();
    // load ssl keys
    //let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    //builder
    //   .set_private_key_file("/keys/key.pem", SslFiletype::PEM)
    //    .unwrap();
    //builder.set_certificate_chain_file("/keys/cert.pem").unwrap();
        
    HttpServer::new(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            //global
            .data(web::JsonConfig::default().limit(1024 * 1024)) // <- limit size of the payload (global configuration)
            // register favicon
            .service(web::resource("/favicon.ico").route(web::get().to(favicon)))
            // with path parameters
            .service(web::resource("/map/{name}").route(web::get().to(map_param)))
            // websocket route
            .service(web::resource("/router/").route(web::get().to(ws_index)))
            // static files
            .service(fs::Files::new("/", &HTML_FOLDER.to_string()).index_file(&FILE_INDEX.to_string()))
            // default
            .default_service(
                // 404 for GET request
                web::resource("")
                    .route(web::get().to(p404))
                    // all requests that are not `GET`
                    .route(
                        web::route()
                            .guard(guard::Not(guard::Get()))
                            .to(HttpResponse::MethodNotAllowed),
                    ),
            )
    })
    // start http server on 127.0.0.1:8081
    //.bind_openssl("127.0.0.1:443", builder)?
    .bind("127.0.0.1:443")?
    .run()
    .await
}