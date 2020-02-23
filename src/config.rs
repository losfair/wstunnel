use crate::util::*;
use jsonwebtoken::DecodingKey;
use serde::Deserialize;
use std::fmt::Debug;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::RangeInclusive;

const IPV4_MAX_DYNRANGE: u32 = 65536;
const IPV6_MAX_DYNRANGE: u128 = 65536;
const IPV4_MAX_PREFIX_LEN: u8 = 32;
const IPV6_MAX_PREFIX_LEN: u8 = 128;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub jwt_key: Option<String>,
    pub rate_limit: Option<RateLimit>,
    pub ipv4: Option<IpConfig<Ipv4Addr>>,
    pub ipv6: Option<IpConfig<Ipv6Addr>>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct RateLimit {
    pub base_kbytes_per_sec: u64,
    pub burst_kbytes: u64,
}

#[derive(Deserialize, Clone, Debug)]
pub struct IpConfig<T> {
    pub range: RangeInclusive<T>,
    pub dynamic_range: RangeInclusive<T>,
    pub me: T,
    pub prefix_length: u8,
}

#[derive(Clone, Debug)]
pub struct PreparedConfig {
    pub jwt_key: Option<DecodingKey<'static>>,
    pub rate_limit: Option<RateLimit>,
    pub ipv4: Option<(IpConfig<Ipv4Addr>, Ipv4Mask)>,
    pub ipv6: Option<IpConfig<Ipv6Addr>>,
}

#[derive(Copy, Clone, Debug)]
pub struct Ipv4Mask(pub Ipv4Addr);

impl Config {
    pub fn prepare_leaky(self) -> Result<PreparedConfig, String> {
        Ok(PreparedConfig {
            jwt_key: if let Some(key) = self.jwt_key {
                Some(
                    DecodingKey::from_rsa_pem(Box::leak(key.into_boxed_str()).as_bytes())
                        .e2s("invalid rsa jwt key")?,
                )
            } else {
                None
            },
            rate_limit: self.rate_limit,
            ipv4: if let Some(ipv4) = self.ipv4 {
                ipv4.validate().e2s("ipv4 validation failed")?;
                if ipv4.dynamic_range_len_minus_one() >= IPV4_MAX_DYNRANGE {
                    return Err("ipv4 dynamic range too large".into());
                }
                if ipv4.prefix_length > IPV4_MAX_PREFIX_LEN {
                    return Err("bad ipv4 prefix length".into());
                }
                if (u32::from(*ipv4.range.start()) >> (IPV4_MAX_PREFIX_LEN - ipv4.prefix_length))
                    != (u32::from(*ipv4.range.end()) >> (IPV4_MAX_PREFIX_LEN - ipv4.prefix_length))
                {
                    return Err("ipv4 prefix length mismatches with range".into());
                }
                let mask = ipv4_prefix_to_mask(ipv4.prefix_length);
                Some((ipv4, mask))
            } else {
                None
            },
            ipv6: if let Some(ipv6) = self.ipv6 {
                ipv6.validate().e2s("ipv6 validation failed")?;
                if ipv6.dynamic_range_len_minus_one() >= IPV6_MAX_DYNRANGE {
                    return Err("ipv6 dynamic range too large".into());
                }
                if ipv6.prefix_length > IPV6_MAX_PREFIX_LEN {
                    return Err("bad ipv6 prefix length".into());
                }
                if (u128::from(*ipv6.range.start()) >> (IPV6_MAX_PREFIX_LEN - ipv6.prefix_length))
                    != (u128::from(*ipv6.range.end()) >> (IPV6_MAX_PREFIX_LEN - ipv6.prefix_length))
                {
                    return Err("ipv6 prefix length mismatches with range".into());
                }
                Some(ipv6)
            } else {
                None
            },
        })
    }
}

impl<T: Ord> IpConfig<T> {
    fn validate(&self) -> Result<(), String> {
        if self.range.start() > self.range.end() {
            return Err("invalid range".into());
        }
        if self.dynamic_range.start() > self.dynamic_range.end() {
            return Err("invalid dynamic range".into());
        }
        if self.dynamic_range.start() < self.range.start()
            || self.dynamic_range.end() > self.range.end()
        {
            return Err("dynamic range must be a subset of the full range".into());
        }
        if !self.range.contains(&self.me) {
            return Err("self address must be contained by the full range".into());
        }
        if self.dynamic_range.contains(&self.me) {
            return Err("self address must not be contained by the dynamic range".into());
        }
        Ok(())
    }
}

impl IpConfig<Ipv4Addr> {
    pub fn dynamic_range_len_minus_one(&self) -> u32 {
        self.dynamic_range_end() - self.dynamic_range_start()
    }

    pub fn dynamic_range_start(&self) -> u32 {
        u32::from(*self.dynamic_range.start())
    }

    pub fn dynamic_range_end(&self) -> u32 {
        u32::from(*self.dynamic_range.end())
    }
}

impl IpConfig<Ipv6Addr> {
    pub fn dynamic_range_len_minus_one(&self) -> u128 {
        self.dynamic_range_end() - self.dynamic_range_start()
    }

    pub fn dynamic_range_start(&self) -> u128 {
        u128::from(*self.dynamic_range.start())
    }

    pub fn dynamic_range_end(&self) -> u128 {
        u128::from(*self.dynamic_range.end())
    }
}

fn ipv4_prefix_to_mask(prefix_len: u8) -> Ipv4Mask {
    assert!(prefix_len <= IPV4_MAX_PREFIX_LEN);
    Ipv4Mask(Ipv4Addr::from(
        (!0u32) << (IPV4_MAX_PREFIX_LEN - prefix_len),
    ))
}
