#[macro_use]
extern crate log;
extern crate env_logger;
extern crate atty;
extern crate hyper;
extern crate base64;
extern crate crypto;
extern crate serde_json;
extern crate serde;
extern crate openssl;
extern crate unix_socket;

use atty::Stream;
use hyper::Client;
use hyper::header::{Authorization, ContentType};
use openssl::crypto::pkey::PKey;
use openssl::crypto::hash::hash;
use openssl::crypto::hash::Type::SHA256;
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::process::exit;
use std::sync::{Arc, RwLock};
use std::thread;
use std::time;
use std::time::{Duration, SystemTime};
use std::ops::Add;
mod types;
use types::{AuthRequestInfo, Token, Claims, Header, ServiceAccountCredentials,
            InstanceAggregatedList, GcpErrors};
use unix_socket::{UnixStream, UnixListener};

const COMPUTE_RO_SCOPE: &'static str = "https://www.googleapis.com/auth/compute.readonly";
const TOKEN_URL: &'static str = "https://www.googleapis.com/oauth2/v4/token";

mod error;
pub use error::Error;

type Result<T> = std::result::Result<T, Error>;

fn instances(token: Token, project: &str) -> Result<InstanceAggregatedList> {
    let mut res = Client::new()
        .get(&format!("https://www.googleapis.com/compute/v1/projects/{}/aggregated/instances",
                      project))
        .header(Authorization(format!("Bearer {}", token.access_token)))
        .send()?;
    let mut buf = String::new();
    res.read_to_string(&mut buf)?;
    serde_json::from_str::<InstanceAggregatedList>(&buf)
        .or_else(|_| {
            Err(Error::GCP(serde_json::from_str::<GcpErrors>(&buf)?))
        })
}

fn base64_enc(bytes: &[u8]) -> String {
    let enc = base64::encode_mode(bytes, base64::Base64Mode::UrlSafe);
    enc[..].trim_right_matches('=').to_owned()
}

fn token(pk: String, email: String, scopes: Vec<String>) -> Result<Token> {
    // build jwt components
    let header = Header {
        alg: String::from("RS256"),
        typ: String::from("JWT"),
    };
    let now = SystemTime::now().duration_since(time::UNIX_EPOCH)?;
    let claims = Claims {
        iss: email,
        scope: scopes.join(" "),
        aud: String::from(TOKEN_URL),
        iat: now.as_secs() as i64,
        exp: now.add(Duration::new(60 * 60, 0)).as_secs() as u32,
    };
    let key = PKey::private_key_from_pem(&mut pk.as_bytes())?;

    // serialize jwt
    let enc_header = base64_enc(&serde_json::to_vec(&header)?);
    let enc_claims = base64_enc(&serde_json::to_vec(&claims)?);
    let signature_base = format!("{}.{}", enc_header, enc_claims);
    let signature = key.sign_with_hash(&hash(SHA256, signature_base.as_bytes()), SHA256);
    let jwt = format!("{}.{}", signature_base, base64_enc(&signature));

    // build token request

    let data = format!(
        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={}",
        jwt
    );
    let mut res = Client::new()
        .post(TOKEN_URL)
        .header(ContentType::form_url_encoded())
        .body(&data)
        .send()
        .unwrap();
    // parse token response
    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();
    Ok(serde_json::from_str::<Token>(&buf)?)
}

fn handle(stream: &mut UnixStream, ips: Arc<RwLock<HashSet<String>>>) {
    println!("handling request");
    let mut request = String::new();
    stream.read_to_string(&mut request).unwrap();
    stream.flush().unwrap();
    println!("done reading '{}'...", request);
    match serde_json::from_str::<AuthRequestInfo>(&request) {
        Ok(auth) => {
            if ips.read().unwrap().contains(&auth.ip) {
                println!("matches");
                stream.write_all(b"true").unwrap();
            } else {
                println!("doesn't match");
                stream.write_all(b"false").unwrap();
            }
            println!("{:?}", auth)
        },
        Err(_) => println!("failed to parse auth")
    }
}

/// starts a listener for auth info requests over a unix domain socket
/// as well as a poller to refresh current snapshot of instance ips
fn serve(credentials_json: String, projects: Vec<&str>) -> Result<()> {
    let credentials = serde_json::from_str::<ServiceAccountCredentials>(&credentials_json)?;
    debug!("loaded credentials for {}", credentials.client_email);
    let listener = UnixListener::bind("auth.sock")?;
    let ips = Arc::new(RwLock::new(HashSet::new()));
    let collectorips = ips.clone();
    let projs = projects.iter().map(|s|s.to_string()).collect::<Vec<_>>();
    thread::spawn(move || {
        loop {
            let credentials = credentials.clone();
            let projs = projs.clone();
            let token = token(credentials.private_key,
                              credentials.client_email,
                              vec![String::from(COMPUTE_RO_SCOPE)]).unwrap();
            let mut writable = collectorips.write().unwrap();
            writable.clear();
            for project in projs {
                debug!("{} project instances", project);
                for (k, instances) in instances(token.clone(), &project).unwrap().items {
                    debug!("region: {}", k);
                    for inst in instances.instances {
                        let netips = inst.network_interfaces
                            .iter()
                            .fold(vec![], |mut acc, interface| {
                                for cfg in interface.clone().access_configs {
                                    if let Some(ip) = cfg.nat_ip {
                                        acc.push(ip)
                                    }
                                }
                                acc
                            });
                        debug!("{}", inst.name);
                        for ip in netips {
                            println!("{}", ip);
                            writable.insert(ip);
                        }
                    }
                }
            }
            drop(writable);
            thread::sleep_ms(10_000)
        }
    });

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                /* connection succeeded */
                let request_ips = ips.clone();
                thread::spawn(move || handle(&mut stream, request_ips));
            }
            Err(err) => {
                /* connection failed */
                println!("no more incoming requests");
                break;
            }
        }
    }

    Ok(())
}

fn request(input: String)  {
    let mut stream = UnixStream::connect("auth.sock").unwrap();
    stream.write_all(input.as_bytes()).unwrap();
    stream.flush().unwrap();
    println!("awaiting response for '{}'...", input);
    std::io::copy(&mut stream, &mut std::io::stdout()).unwrap();
    //let mut response = String::new();
    //stream.read_to_string(&mut response).unwrap();
    //println!("response {}", response);
}

fn main() {
    env_logger::init().unwrap();
    match (env::var("GCP_CREDENTIALS"), env::var("GCP_PROJECTS")) {
        (Ok(credentials), Ok(projects)) => {
            match env::args().nth(1) {
                Some(_) => {
                    let mut input = String::new();
                    io::stdin().read_line(&mut input).unwrap();
                    println!("going to request {}", input);
                    request(input);
                },
                _ => {
                    match serve(credentials, projects.split(",").collect()) {
                        Err(err) => {
                            println!("error {:?}", err);
                            exit(1)
                        }, _ => ()
                    }
                }
            }
        },
        _ => exit(1),
    }
}
