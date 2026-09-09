//! Bounded evidence decoding with duplicate keys rejected at every depth.
use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};

use crate::Result;

struct Unique(Value);

impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct Values;
        impl<'de> Visitor<'de> for Values {
            type Value = Unique;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("unambiguous JSON")
            }

            fn visit_bool<E: de::Error>(self, value: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(value)))
            }

            fn visit_i64<E: de::Error>(self, value: i64) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }

            fn visit_u64<E: de::Error>(self, value: u64) -> std::result::Result<Unique, E> {
                Ok(Unique(value.into()))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> std::result::Result<Unique, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| Unique(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite evidence number"))
            }

            fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(value.to_owned())))
            }

            fn visit_string<E: de::Error>(self, value: String) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(value)))
            }

            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Vec::new();
                while let Some(Unique(value)) = seq.next_element()? {
                    if values.len() >= 4096 {
                        return Err(de::Error::custom("evidence array limit"));
                    }
                    values.push(value);
                }
                Ok(Unique(Value::Array(values)))
            }

            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut values = Map::new();
                while let Some((key, Unique(value))) = map.next_entry::<String, Unique>()? {
                    if values.len() >= 4096 || values.insert(key, value).is_some() {
                        return Err(de::Error::custom("duplicate key or evidence object limit"));
                    }
                }
                Ok(Unique(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Values)
    }
}

pub(crate) fn decode(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > 1024 * 1024 {
        return Err("evidence exceeds byte bound".into());
    }
    // serde_json's recursion limit remains enabled; errors never echo input.
    serde_json::from_slice::<Unique>(bytes)
        .map(|value| value.0)
        .map_err(|_| "evidence JSON is malformed, ambiguous or exceeds structural bounds".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_at_any_depth_and_trailing_input_are_rejected() {
        for input in [
            r#"{"passed":false,"passed":true}"#,
            r#"{"checks":{"a":false,"a":true}}"#,
            r#"[{"x":0,"\u0078":1}]"#,
            "{}{}",
        ] {
            assert!(decode(input.as_bytes()).is_err());
        }
        assert!(decode(br#"{"u":18446744073709551615,"a":[true,null,0.5,-1]}"#).is_ok());
        assert!(decode(&vec![b' '; 1024 * 1024 + 1]).is_err());
        assert!(decode(format!("{}0{}", "[".repeat(130), "]".repeat(130)).as_bytes()).is_err());
    }
}
