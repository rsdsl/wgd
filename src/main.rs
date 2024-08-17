use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr};
use std::thread;

use rsdsl_netlinklib::blocking::Connection;
use thiserror::Error;
use wireguard_control::{AllowedIp, Backend, DeviceUpdate, Key, KeyPair, PeerConfigBuilder};

const IFNAME: &str = "wg0";
const INNER_ADDRESS: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 128, 50, 254));
const PORT: u16 = 51820;
const CONFIGFILE_PRIVATEKEY: &str = "/data/wgd.key";
const CONFIGFILE_PEERS: &str = "/data/wgd.peers";

#[derive(Debug, Error)]
enum Error {
    #[error(
        "too few peer config columns (want <name> <pubkey> <psk> <allowed-ip> [allowed-ip...])"
    )]
    TooFewPeerColumns,
    #[error("invalid allowed ip {0}")]
    InvalidAllowedIp(String),

    #[error("io: {0}")]
    Io(#[from] io::Error),

    #[error("invalid base64 key: {0}")]
    InvalidKey(String),
    #[error("rsdsl_netlinklib: {0}")]
    RsdslNetlinklib(#[from] rsdsl_netlinklib::Error),
}

type Result<T> = std::result::Result<T, Error>;

fn main() -> Result<()> {
    println!("[info] init");

    let connection = Connection::new()?;

    if !connection.link_exists(String::from(IFNAME))? {
        connection.link_add_wireguard(String::from(IFNAME))?;
        println!("[info] create link {}", IFNAME);
    } else {
        println!("[info] link {} exists", IFNAME);
    }

    let keypair = read_or_generate_keypair()?;
    println!("[info] pubkey {}", keypair.public.to_base64());

    configure_link(&connection, keypair)?;
    println!("[info] config {}", IFNAME);

    loop {
        thread::park();
    }
}

fn configure_link(connection: &Connection, keypair: KeyPair) -> Result<()> {
    unconfigure_link(connection)?;
    println!("[info] unconfig {}", IFNAME);

    DeviceUpdate::new()
        .add_peers(&read_peers()?)
        .set_listen_port(PORT)
        .set_keypair(keypair)
        .apply(&IFNAME.parse().expect("valid link name"), Backend::Kernel)?;

    connection.address_add(String::from(IFNAME), INNER_ADDRESS, 24)?;

    Ok(())
}

fn unconfigure_link(connection: &Connection) -> Result<()> {
    connection.address_flush(String::from(IFNAME))?;

    DeviceUpdate::new()
        .replace_peers()
        .set_listen_port(PORT)
        .unset_fwmark()
        .unset_private_key()
        .unset_public_key()
        .apply(&IFNAME.parse().expect("valid link name"), Backend::Kernel)?;

    Ok(())
}

fn read_or_generate_keypair() -> Result<KeyPair> {
    match read_keypair() {
        Ok(keypair) => Ok(keypair),
        Err(e) => {
            println!("[warn] unable to read keypair: {}", e);
            generate_and_save_keypair()
        }
    }
}

fn read_keypair() -> Result<KeyPair> {
    let private_base64 = fs::read_to_string(CONFIGFILE_PRIVATEKEY)?;
    let private_key =
        Key::from_base64(&private_base64).map_err(|_| Error::InvalidKey(private_base64))?;
    Ok(KeyPair::from_private(private_key))
}

fn generate_and_save_keypair() -> Result<KeyPair> {
    let keypair = KeyPair::generate();
    fs::write(CONFIGFILE_PRIVATEKEY, keypair.private.to_base64())?;
    Ok(keypair)
}

fn read_peers() -> Result<Vec<PeerConfigBuilder>> {
    let file = File::open(CONFIGFILE_PEERS)?;
    let br = BufReader::new(file);

    let mut peers = Vec::new();

    for line in br.lines() {
        let line = line?;

        let mut columns = line.split_whitespace();

        // Discard human-readable peer name
        columns.next().ok_or(Error::TooFewPeerColumns)?;
        let public_key_base64 = columns.next().ok_or(Error::TooFewPeerColumns)?;
        let preshared_key_base64 = columns.next().ok_or(Error::TooFewPeerColumns)?;

        let public_key = Key::from_base64(public_key_base64)
            .map_err(|_| Error::InvalidKey(public_key_base64.to_string()))?;
        let preshared_key = Key::from_base64(preshared_key_base64)
            .map_err(|_| Error::InvalidKey(preshared_key_base64.to_string()))?;

        let mut builder = PeerConfigBuilder::new(&public_key)
            .replace_allowed_ips()
            .set_preshared_key(preshared_key);

        for column in columns {
            let allowed_ip: AllowedIp = column
                .parse()
                .map_err(|_| Error::InvalidAllowedIp(column.to_string()))?;
            builder = builder.add_allowed_ip(allowed_ip.address, allowed_ip.cidr);
        }

        peers.push(builder);
    }

    Ok(peers)
}
