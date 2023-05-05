use cloudflare::{
    endpoints::{
        dns::{
            DnsContent, ListDnsRecords, ListDnsRecordsParams, UpdateDnsRecord,
            UpdateDnsRecordParams,
        },
        zone,
    },
    framework::{auth::Credentials, Environment, HttpApiClient, HttpApiClientConfig, SearchMatch},
};
use lazy_static::lazy_static;
use regex::Regex;
use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::exit;

use serde::Deserialize;
use serde_qs::from_str;
use tiny_http::{Response, Server};

#[derive(Deserialize)]
struct Query {
    ip4: Option<Ipv4Addr>,
    ip6: Option<Ipv6Addr>,
}

#[derive(Debug)]
struct IpSomething<A> {
    record_id: String,
    ip: A,
}

#[derive(Debug)]
struct Domain {
    zone: String,
    domain: String,
    ip4: Option<IpSomething<Ipv4Addr>>,
    ip6: Option<IpSomething<Ipv6Addr>>,
}

fn main() {
    let client = HttpApiClient::new(
        Credentials::UserAuthToken {
            token: env::var("API_TOKEN").expect("Missing 'API_TOKEN' environment variable."),
        },
        HttpApiClientConfig::default(),
        Environment::Production,
    )
    .expect("Failed to create cloudflare client");

    fn get_zone(domain: &str, cf: &HttpApiClient) -> String {
        lazy_static! {
            static ref RE: Regex = Regex::new(r"[^.]*\.[^.]{2,3}(?:\.[^.]{2,3})?$").unwrap();
        }
        let root_domain = RE
            .find(domain)
            .expect(format!("Couldnt parse root domain for {}", domain).as_str())
            .as_str();
        let zones = cf
            .request(&zone::ListZones {
                params: zone::ListZonesParams {
                    name: Some(root_domain.into()),
                    status: None,
                    page: None,
                    per_page: None,
                    order: None,
                    direction: None,
                    search_match: Some(SearchMatch::Any),
                },
            })
            .expect(format!("Couldn't fetch zone information for '{}'.", domain).as_str())
            .result;
        if zones.len() != 1 {
            println!(
                "Got an invalid number of zone results ({}) for {}",
                zones.len(),
                domain
            );
            exit(1);
        }
        zones[0].id.clone()
    }

    let str_records = env::var("DOMAINS").expect("Missing 'DOMAINS' environment variable.");
    let domains = str_records
        .split(' ')
        .into_iter()
        .map(|domain| {
            let zone = get_zone(domain, &client);
            let records = client
                .request(&ListDnsRecords {
                    zone_identifier: zone.as_str(),
                    params: ListDnsRecordsParams {
                        name: Some(domain.to_string()),
                        record_type: None,
                        page: None,
                        per_page: None,
                        order: None,
                        direction: None,
                        search_match: None,
                    },
                })
                .expect(format!("Failed to query record id for domain {}", domain).as_str())
                .result;
            if records.len() == 0 {
                println!("Got 0 record results for domain {}", domain);
                exit(1);
            };
            let mut ip4: Option<IpSomething<Ipv4Addr>> = None;
            let mut ip6: Option<IpSomething<Ipv6Addr>> = None;
            for record in records {
                let content = record.content;
                match content {
                    DnsContent::A { content: ip } => {
                        ip4 = Some(IpSomething {
                            record_id: record.id,
                            ip,
                        });
                    }
                    DnsContent::AAAA { content: ip } => {
                        ip6 = Some(IpSomething {
                            record_id: record.id,
                            ip,
                        })
                    }
                    _ => {}
                }
            }
            Domain {
                zone,
                domain: domain.to_string(),
                ip4,
                ip6,
            }
        })
        .clone();

    println!("Using these dns records:");
    for domain in domains.clone() {
        println!("\t{}:", domain.domain);
        if domain.ip4.is_some() {
            println!("\t\tipv4: {}", domain.ip4.unwrap().ip);
        }
        if domain.ip6.is_some() {
            println!("\t\tipv6: {}", domain.ip6.unwrap().ip);
        }
    }

    let interface = env::var("INTERFACE").unwrap_or("0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or("8080".to_string());
    let server = Server::http(format!("{}:{}", interface, port)).unwrap();
    println!("Listening on {}:{}", interface, port);

    for request in server.incoming_requests() {
        let ip: Query = match from_str(&request.url()[2..]) {
            Ok(e) => e,
            Err(_) => {
                let res = Response::from_string("Failed to parse query parameters.\n");
                request.respond(res).unwrap();
                continue;
            }
        };
        let mut is_failure = false;
        for domain in domains.clone() {
            if ip.ip4.is_some() && domain.ip4.is_some() {
                let ip = ip.ip4.unwrap();
                let record = domain.ip4.unwrap();
                if ip != record.ip {
                    println!("Updating {} with ip {}", domain.domain, ip);
                    match client.request(&UpdateDnsRecord {
                        zone_identifier: domain.zone.as_str(),
                        identifier: record.record_id.as_str(),
                        params: UpdateDnsRecordParams {
                            ttl: Some(1),
                            proxied: Some(false),
                            name: domain.domain.as_str(),
                            content: DnsContent::A { content: ip },
                        },
                    }) {
                        Ok(a) => a,
                        Err(e) => {
                            println!("Failed to update record {} with ip {}", domain.domain, ip);
                            println!("{:#?}", e);
                            is_failure = true;
                            continue;
                        }
                    };
                }
            }
            if ip.ip6.is_some() && domain.ip6.is_some() {
                let ip = ip.ip6.unwrap();
                let record = domain.ip6.unwrap();
                if ip != record.ip {
                    println!("Updating {} with ip {}", domain.domain, ip);
                    match client.request(&UpdateDnsRecord {
                        zone_identifier: domain.zone.as_str(),
                        identifier: record.record_id.as_str(),
                        params: UpdateDnsRecordParams {
                            ttl: Some(1),
                            proxied: Some(false),
                            name: domain.domain.as_str(),
                            content: DnsContent::AAAA { content: ip },
                        },
                    }) {
                        Ok(a) => a,
                        Err(e) => {
                            println!("Failed to update record {} with ip {}", domain.domain, ip);
                            println!("{:#?}", e);
                            is_failure = true;
                            continue;
                        }
                    };
                }
            }
        }
        if is_failure {
            let response = Response::from_string("Failed to update DNS records.\n")
                .with_status_code(tiny_http::StatusCode(500));
            request.respond(response).unwrap();
        } else {
            let response = Response::from_string("ok\n");
            request.respond(response).unwrap();
        }
    }
}
