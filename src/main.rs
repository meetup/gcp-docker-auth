extern crate hyper;
extern crate base64;
extern crate crypto;
extern crate serde_json;
extern crate serde;
extern crate openssl;
extern crate url;

use hyper::Client;
use hyper::header::{Authorization, ContentType};
use openssl::crypto::pkey::PKey;
use openssl::crypto::hash::hash;
use openssl::crypto::hash::Type::SHA256;
use std::env;
use std::io::Read;
use std::time;
use std::time::{Duration, SystemTime};
use std::ops::Add;
use url::form_urlencoded;

mod types;
use types::{Token, Claims, Header, ServiceAccountCredentials, InstanceAggregatedList};



fn instances(token: Token, project: &str) -> InstanceAggregatedList {
    let mut res = Client::new()
        .get(&format!("https://www.googleapis.com/compute/v1/projects/{}/aggregated/instances",
                      project))
        .header(Authorization(format!("Bearer {}", token.access_token)))
        .send()
        .unwrap();
    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();
    // println!("{}", buf);
    // todo: handle invalid project name
    serde_json::from_str::<InstanceAggregatedList>(&buf).unwrap()
}

fn base64_enc(bytes: &[u8]) -> String {
    let enc = base64::encode_mode(bytes, base64::Base64Mode::UrlSafe);
    enc[..].trim_right_matches('=').to_owned()
}

fn token(pk: String, email: String, scopes: Vec<String>) -> Token {
    // build jwt components
    let header = Header {
        alg: String::from("RS256"),
        typ: String::from("JWT"),
    };
    let now = SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
    let claims = Claims {
        iss: email,
        scope: scopes.join(" "),
        aud: String::from("https://www.googleapis.com/oauth2/v4/token"),
        iat: now.as_secs() as i64,
        exp: now.add(Duration::new(60 * 60, 0)).as_secs() as u32,
    };
    let key = PKey::private_key_from_pem(&mut pk.as_bytes()).unwrap();

    // serialize jwt
    let enc_header = base64_enc(serde_json::to_string(&header).unwrap().as_bytes());
    let enc_claims = base64_enc(serde_json::to_string(&claims).unwrap().as_bytes());
    let signature_base = format!("{}.{}", enc_header, enc_claims);
    let signature = key.sign_with_hash(&hash(SHA256, signature_base.as_bytes()), SHA256);
    let jwt = format!("{}.{}", signature_base, base64_enc(&signature));

    // build token request
    let data = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(vec![("grant_type",
                            "urn:ietf:params:oauth:grant-type:jwt-bearer".to_owned()),
                           ("assertion", jwt)])
        .finish();
    let mut res = Client::new()
        .post("https://www.googleapis.com/oauth2/v4/token")
        .header(ContentType::form_url_encoded())
        .body(&data)
        .send()
        .unwrap();
    // parse token response
    let mut buf = String::new();
    res.read_to_string(&mut buf).unwrap();
    serde_json::from_str::<Token>(&buf).unwrap()
}

fn main() {
    match (env::var("GCP_CREDENTIALS"), env::var("GCP_PROJECTS")) {
        (Ok(credentials), Ok(projects)) => {
            match serde_json::from_str::<ServiceAccountCredentials>(&credentials) {
                Ok(credentials) => {
                    println!("loaded credentials for {}", credentials.client_email);
                    let token = token(credentials.private_key,
                                      credentials.client_email,
                                      vec![String::from("https://www.googleapis.\
                                                         com/auth/compute.readonly")]);
                    for project in projects.split(",") {
                        println!("{} project instances", project);
                        for (k, instances) in instances(token.clone(), project).items {
                            println!("region: {}", k);
                            for inst in instances.instances {
                                let ips = inst.network_interfaces
                                    .iter()
                                    .fold(vec![], |mut acc, interface| {
                                        for cfg in interface.clone().access_configs {
                                            acc.push(cfg.nat_ip)
                                        }
                                        acc
                                    });
                                println!("  {} ({})", ips.join(" "), inst.name);
                            }
                        }
                    }
                }
                Err(err) => println!("failed to parse credentials: {}", err),
            }
        }
        _ => (),
    }
}
