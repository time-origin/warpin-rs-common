use anyhow::{Result, anyhow};

pub fn ensure_non_empty(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(anyhow!("{field} must not be empty"));
    }

    Ok(())
}

pub fn ensure_unique_absent(exists: bool, field: &str, value: &str) -> Result<()> {
    if exists {
        return Err(anyhow!("{field} already exists: {value}"));
    }

    Ok(())
}
