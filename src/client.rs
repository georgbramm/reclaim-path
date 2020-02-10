#[macro_use]
extern crate clap;
extern crate osm_xml as osm;
mod schemes;
mod utils;

use clap::{App, Arg, ArgMatches, SubCommand};
use std::error::Error;
use std::fmt;
use schemes::chase::matrix::SE;
use utils::prf::PRF;
use utils::prp::PRP;
use std::path::Path;
use std::process;
use std::fs::File;

const EXTENSION_JSON: &'static str = "json";
const EXTENSION_OSM: &'static str = "osm";
const OSM_FILE: &'static str = "campus-garching";
const KEY_FILE: &'static str = "se-key";
const SYSTEM_FILE: &'static str = "se-system";
const CT_FILE: &'static str = "se-ciphertext";
const PT_FILE: &'static str = "se-object";
const KEY_BEGIN: &'static str = "-----BEGIN SE KEY-----\n";
const KEY_END: &'static str = "\n-----END SE KEY-----";

const CT_BEGIN: &'static str = "-----BEGIN SE CIPHERTEXT-----\n";
const CT_END: &'static str = "\n-----END SE CIPHERTEXT-----";
const DOT: &'static str = ".";

// Application commands
const CMD_SETUP: &'static str = "setup";
const CMD_SETUP_ARG_1: &'static str = "file";
const CMD_SETUP_ARG_2: &'static str = "name";
const CMD_KEYGEN: &'static str = "keygen";
const CMD_KEYGEN_ARG_1: &'static str = "file";
const CMD_ENCRYPT: &'static str = "encrypt";
const CMD_ENCRYPT_ARG_1: &'static str = "file";
const CMD_ENCRYPT_ARG_2: &'static str = "output";
const CMD_ENCRYPT_ARG_3: &'static str = "key";
const CMD_DECRYPT: &'static str = "decrypt";
const CMD_DECRYPT_ARG_1: &'static str = "object";
const CMD_DECRYPT_ARG_2: &'static str = "key";
const CMD_TOKEN: &'static str = "token";
const CMD_TOKEN_ARG_1: &'static str = "type";
const CMD_TOKEN_ARG_2: &'static str = "name";
const CMD_TOKEN_ARG_3: &'static str = "key";
const CMD_LOOKUP: &'static str = "lookup";
const CMD_LOOKUP_ARG_1: &'static str = "token";




#[derive(Debug)]
struct RustSEError {
    details: String,
}

impl RustSEError {
    fn new(msg: &str) -> RustSEError {
        RustSEError { details: msg.to_string() }
    }
}

impl fmt::Display for RustSEError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: {}", self.details)
    }
}

impl Error for RustSEError {
    fn description(&self) -> &str {
        &self.details
    }
}

fn main() {
    arg_enum! {
        #[derive(Debug)]
		enum ObjectType {
		    Way,
		    Node,
		}
    }

    // Default file names
    let _key_default = [KEY_FILE, DOT, EXTENSION_JSON].concat();
    let _system_default = [SYSTEM_FILE, DOT, EXTENSION_JSON].concat();
    let _pt_default = [PT_FILE, DOT, EXTENSION_JSON].concat();
    let _input_default = [OSM_FILE, DOT, EXTENSION_OSM].concat();
    let _output_default = [CT_FILE, DOT, EXTENSION_JSON].concat();

    let _abe_app = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .subcommand(
            // Keygen
            SubCommand::with_name(CMD_SETUP)
                .about(
                    "sets up a new se scheme and generates the corresponding system key.",
                )
                .arg(
                    Arg::with_name(CMD_SETUP_ARG_1)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_system_default)
                        .help("the system key file."),
                )
                .arg(
                    Arg::with_name(CMD_SETUP_ARG_2)
                        .required(true)
                        .takes_value(true)
                        .help("the system key file."),
                ),
        )
        .subcommand(
            // Keygen
            SubCommand::with_name(CMD_KEYGEN)
                .about("generates a new key.")
                .arg(
                    Arg::with_name(CMD_KEYGEN_ARG_1)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_key_default)
                        .help("the secret key file."),
                ),
        )
        .subcommand(
            // Encrypt
            SubCommand::with_name(CMD_ENCRYPT)
                .about("encrypts an open street map in osm/xml format..")
                .arg(
                    Arg::with_name(CMD_ENCRYPT_ARG_1)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_input_default)
                        .help("the osm file to use."),
                )
                .arg(
                    Arg::with_name(CMD_ENCRYPT_ARG_2)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_input_default)
                        .help("."),
                )
                .arg(
                    Arg::with_name(CMD_ENCRYPT_ARG_3)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_key_default)
                        .help("the key used to encrypt."),
                ),
        )
        .subcommand(
            // Decrypt
            SubCommand::with_name(CMD_DECRYPT)
                .about("Decrypts an object (either Edge or Vertex).")
                .arg(
                    Arg::with_name(CMD_DECRYPT_ARG_1)
                        .required(true)
                        .takes_value(true)
                        .default_value(&_pt_default)
                        .help("the json file to export the decrypted object to."),
                )
                .arg(
                    Arg::with_name(CMD_ENCRYPT_ARG_2)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_key_default)
                        .help("the key used to encrypt."),
                ),
        )
        .subcommand(
            // Token
            SubCommand::with_name(CMD_TOKEN)
                .about("Generates a lookup token (either Edge or Vertex).")
                .arg(
                    Arg::with_name(CMD_TOKEN_ARG_1)
                        .required(true)
                        .takes_value(true)
                        .possible_values(&ObjectType::variants())
                        .help("Type of token to generate."),
                )
                .arg(
                    Arg::with_name(CMD_TOKEN_ARG_2)
                        .required(true)
                        .takes_value(true)
                        .help("the value to search for."),
                )
                .arg(
                    Arg::with_name(CMD_TOKEN_ARG_3)
                        .required(false)
                        .takes_value(true)
                        .default_value(&_key_default)
                        .help("the key used to encrypt."),
                ),
        )
        .subcommand(
            // Lookup
            SubCommand::with_name(CMD_LOOKUP)
                .about(
                    "Looks up the results of a token based search (either Edge or Vertex).",
                )
                .arg(
                    Arg::with_name(CMD_LOOKUP_ARG_1)
                        .required(true)
                        .takes_value(true)
                        .help("The token to use for the search."),
                ),
        )
        .get_matches();

    if let Err(e) = run(_abe_app) {
        println!("Application error: {}", e);
        process::exit(1);
    }

    fn run(matches: ArgMatches) -> Result<(), RustSEError> {
        match matches.subcommand() {
            (CMD_SETUP, Some(matches)) => run_setup(matches),
            (CMD_KEYGEN, Some(matches)) => run_keygen(matches),
            (CMD_ENCRYPT, Some(matches)) => run_encrypt(matches),
            (CMD_DECRYPT, Some(matches)) => run_decrypt(matches),
            (CMD_TOKEN, Some(matches)) => {
                let _token = value_t!(matches.value_of(CMD_TOKEN_ARG_1), ObjectType).unwrap();
                run_token(matches, _token)
            }
            (CMD_LOOKUP, Some(matches)) => run_lookup(matches),
            _ => Ok(()),
        }
    }

    fn run_setup(arguments: &ArgMatches) -> Result<(), RustSEError> {
        let mut _key_file = String::from("");
        let mut _name = String::from("");
        match arguments.value_of(CMD_SETUP_ARG_1) {
            None => {
                _key_file.push_str(&KEY_FILE);
                _key_file.push_str(&DOT);
                _key_file.push_str(&EXTENSION_JSON);
            }
            Some(_file) => _key_file = _file.to_string(),
        }
        match arguments.value_of(CMD_SETUP_ARG_2) {
            None => {
                _name.push_str(&KEY_FILE);
                _name.push_str(&DOT);
                _name.push_str(&EXTENSION_JSON);
            }
            Some(_file) => _name = _file.to_string(),
        }
        let _se = SE::new(_name);
        Ok(())
    }

    fn run_keygen(arguments: &ArgMatches) -> Result<(), RustSEError> {
        let mut _key_file = String::from("");
        match arguments.value_of(CMD_KEYGEN_ARG_1) {
            None => {
                _key_file.push_str(&KEY_FILE);
                _key_file.push_str(&DOT);
                _key_file.push_str(&EXTENSION_JSON);
            }
            Some(_file) => _key_file = _file.to_string(),
        }
        let _key = SE::keygen().unwrap();
        println!("Your key is:\n{:?}", _key);
        Ok(())
    }

    fn run_encrypt(arguments: &ArgMatches) -> Result<(), RustSEError> {
        let mut _file = String::from("");
        let mut _name = String::from("");
        let mut _key = String::from("");
        match arguments.value_of(CMD_ENCRYPT_ARG_1) {
            None => {
                _file.push_str(&KEY_FILE);
                _file.push_str(&DOT);
                _file.push_str(&EXTENSION_JSON);
            }
            Some(_files) => _file = _files.to_string(),
        }
        match arguments.value_of(CMD_ENCRYPT_ARG_2) {
            None => {
                _name.push_str(&OSM_FILE);
            }
            Some(name) => _name = name.to_string(),
        }
        match arguments.value_of(CMD_ENCRYPT_ARG_3) {
            None => {
                _file.push_str(&KEY_FILE);
                _file.push_str(&DOT);
                _file.push_str(&EXTENSION_JSON);
            }
            Some(name) => _name = _key.to_string(),
        }
        let f = File::open(&_file).unwrap();
        let doc = osm::OSM::parse(f).unwrap();
        let rel_info = relation_reference_statistics(&doc);
        let way_info = way_reference_statistics(&doc);
        let poly_count = doc.ways.values().fold(0, |acc, way| {
            if way.is_polygon() {
                return acc + 1;
            }
            acc
        });
        let highway_count = doc.ways.values().fold(0, |acc, way| {
            if way.is_highway() {
                return acc + 1;
            }
            acc
        });


        println!("Node count {}", doc.nodes.len());
        println!("Polygon count {}", poly_count);
        println!("Relation count {}", doc.relations.len());
        println!("Tag count {}", tag_count(&doc));
        //println!("Highway count {}", highway_count);
        println!(
            "Way reference count: {}, invalid references: {}",
            way_info.0,
            way_info.1
        );
        println!(
            "Relation reference count: {}, resolved: {}, unresolved: {}",
            rel_info.0,
            rel_info.1,
            rel_info.2
        );
        Ok(())
    }

    fn run_decrypt(arguments: &ArgMatches) -> Result<(), RustSEError> {
        Ok(())
    }

    fn run_lookup(arguments: &ArgMatches) -> Result<(), RustSEError> {
        Ok(())
    }

    fn run_token(arguments: &ArgMatches, _type: ObjectType) -> Result<(), RustSEError> {
        Ok(())
    }
}


fn relation_reference_statistics(doc: &osm::OSM) -> (usize, usize, usize) {
    doc.relations
        .values()
        .flat_map(|relation| relation.members.iter())
        .fold((0, 0, 0), |acc, member| {
            let el_ref = match *member {
                osm::Member::Node(ref el_ref, _) => el_ref,
                osm::Member::Way(ref el_ref, _) => el_ref,
                osm::Member::Relation(ref el_ref, _) => el_ref,
            };

            match doc.resolve_reference(&el_ref) {
                osm::Reference::Unresolved => (acc.0 + 1, acc.1, acc.2 + 1),
                osm::Reference::Node(_) |
                osm::Reference::Way(_) |
                osm::Reference::Relation(_) => (acc.0 + 1, acc.1 + 1, acc.2),
            }
        })
}

fn way_reference_statistics(doc: &osm::OSM) -> (usize, usize) {
    doc.ways.values().flat_map(|way| way.nodes.iter()).fold(
        (0, 0),
        |acc,
         node| {
            match doc.resolve_reference(&node) {
                osm::Reference::Node(_) => (acc.0 + 1, acc.1),
                osm::Reference::Unresolved |
                osm::Reference::Way(_) |
                osm::Reference::Relation(_) => (acc.0, acc.1 + 1),
            }
        },
    )
}

fn tag_count(doc: &osm::OSM) -> usize {
    let node_tag_count = doc.nodes.values().map(|node| node.tags.len()).fold(
        0,
        |acc, c| {
            acc + c
        },
    );
    let way_tag_count = doc.ways.values().map(|way| way.tags.len()).fold(
        0,
        |acc, c| acc + c,
    );
    let relation_tag_count = doc.relations
        .values()
        .map(|relation| relation.tags.len())
        .fold(0, |acc, c| acc + c);

    node_tag_count + way_tag_count + relation_tag_count
}
