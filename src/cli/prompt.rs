use std::io::{BufRead, Write};

use anyhow::{Context, Result};

pub(crate) struct Prompt<'a> {
    input: &'a mut dyn BufRead,
    output: &'a mut dyn Write,
}

impl<'a> Prompt<'a> {
    pub(crate) fn new(input: &'a mut dyn BufRead, output: &'a mut dyn Write) -> Self {
        Self { input, output }
    }

    pub(crate) fn prompt_text(&mut self, label: &str, default: Option<&str>) -> Result<String> {
        let prompt = format_prompt(label, default);
        let mut line = String::new();
        write!(self.output, "{prompt}").context("Failed to write prompt")?;
        self.output.flush().context("Failed to flush prompt")?;
        self.input
            .read_line(&mut line)
            .context("Failed to read prompt input")?;
        let trimmed = line.trim();
        if trimmed.is_empty()
            && let Some(value) = default
        {
            return Ok(value.to_string());
        }
        Ok(trimmed.to_string())
    }

    pub(crate) fn prompt_with_validation<T, F>(
        &mut self,
        label: &str,
        default: Option<&str>,
        mut validate: F,
    ) -> Result<T>
    where
        F: FnMut(&str) -> Result<T>,
    {
        loop {
            let value = self.prompt_text(label, default)?;
            match validate(&value) {
                Ok(parsed) => return Ok(parsed),
                Err(err) => {
                    writeln!(self.output, "{err}").context("Failed to write prompt error")?;
                }
            }
        }
    }
}

fn format_prompt(label: &str, default: Option<&str>) -> String {
    match default {
        Some(value) => format!("{label} [{value}]: "),
        None => format!("{label}: "),
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn prompt_text_uses_default_on_blank() {
        let mut input = Cursor::new("\n");
        let mut output = Vec::new();
        let mut prompt = Prompt::new(&mut input, &mut output);
        let value = prompt.prompt_text("Label", Some("default")).unwrap();
        assert_eq!(value, "default");
    }

    #[test]
    fn prompt_text_reads_value() {
        let mut input = Cursor::new("value\n");
        let mut output = Vec::new();
        let mut prompt = Prompt::new(&mut input, &mut output);
        let value = prompt.prompt_text("Label", Some("default")).unwrap();
        assert_eq!(value, "value");
    }
}
