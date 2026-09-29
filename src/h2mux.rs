use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

/// Client preference shared by managed profiles and Chain Proxy nodes.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default)]
pub struct H2MuxOptions {
    pub enabled: bool,
    pub max_connections: u32,
    pub min_streams: u32,
    pub max_streams: u32,
    pub padding: bool,
}

impl Default for H2MuxOptions {
    fn default() -> Self {
        Self {
            enabled: false,
            max_connections: 4,
            min_streams: 4,
            max_streams: 0,
            padding: false,
        }
    }
}

impl H2MuxOptions {
    pub fn is_disabled(&self) -> bool {
        !self.enabled
    }

    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_streams == 0 {
            if self.max_connections == 0 || self.min_streams == 0 {
                bail!("H2MUX 连接数模式要求 max_connections 和 min_streams 均至少为 1");
            }
        } else if self.max_connections != 0 || self.min_streams != 0 {
            bail!("H2MUX max_streams 模式不能同时设置 max_connections 或 min_streams");
        }
        if self.max_connections > 1024 || self.min_streams > 65535 || self.max_streams > 65535 {
            bail!("H2MUX 参数超过安全上限");
        }
        Ok(())
    }

    pub fn shoes_value(&self) -> Result<serde_yaml::Value> {
        self.validate()?;
        if !self.enabled {
            bail!("不能为关闭的 H2MUX 生成 shoes 配置");
        }
        Ok(serde_yaml::to_value(json!({
            "max_connections": self.max_connections,
            "min_streams": self.min_streams,
            "max_streams": self.max_streams,
            "padding": self.padding,
        }))?)
    }

    pub fn sing_box_value(&self) -> Result<Value> {
        self.validate()?;
        if !self.enabled {
            bail!("不能为关闭的 H2MUX 生成 sing-box 配置");
        }
        Ok(json!({
            "enabled": true,
            "protocol": "h2mux",
            "max_connections": self.max_connections,
            "min_streams": self.min_streams,
            "max_streams": self.max_streams,
            "padding": self.padding,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_exclusive_modes() {
        let mut options = H2MuxOptions::default();
        assert!(options.is_disabled());
        options.enabled = true;
        options.validate().unwrap();
        assert!(options.shoes_value().unwrap().get("enabled").is_none());
        assert_eq!(options.sing_box_value().unwrap()["protocol"], "h2mux");
        options.max_connections = 0;
        assert!(options.validate().is_err());
        options.max_connections = 4;
        options.min_streams = 0;
        assert!(options.validate().is_err());
        options.min_streams = 4;
        options.max_streams = 8;
        assert!(options.validate().is_err());
        options.max_connections = 0;
        options.min_streams = 0;
        options.validate().unwrap();
    }
}
