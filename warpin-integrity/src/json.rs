use std::collections::HashSet;

use crate::capture::CapturedValue;
use crate::number::parse_json_number;
use crate::{CanonicalProfile, IntegrityError};

const MAX_INPUT_BYTES: usize = 1_048_576;
const MAX_NESTING_DEPTH: usize = 128;
const MAX_NUMBER_BYTES: usize = 1_024;
const MAX_STRING_BYTES: usize = 262_144;

pub(crate) fn parse_captured_json(
    input: &str,
    profile: CanonicalProfile,
) -> Result<CapturedValue, IntegrityError> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(IntegrityError::InvalidJson { line: 1, column: 1 });
    }
    let mut parser = Parser {
        input,
        bytes: input.as_bytes(),
        index: 0,
        profile,
    };
    parser.skip_whitespace();
    let value = parser.parse_value(0)?;
    parser.skip_whitespace();
    if parser.index != parser.bytes.len() {
        return Err(parser.invalid());
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    index: usize,
    profile: CanonicalProfile,
}

impl Parser<'_> {
    fn parse_value(&mut self, depth: usize) -> Result<CapturedValue, IntegrityError> {
        if depth > MAX_NESTING_DEPTH {
            return Err(self.invalid());
        }
        self.skip_whitespace();
        match self.peek() {
            Some(b'n') => self.parse_literal(b"null", CapturedValue::Null),
            Some(b't') => self.parse_literal(b"true", CapturedValue::Bool(true)),
            Some(b'f') => self.parse_literal(b"false", CapturedValue::Bool(false)),
            Some(b'"') => self.parse_string().map(CapturedValue::String),
            Some(b'[') => self.parse_array(depth + 1),
            Some(b'{') => self.parse_object(depth + 1),
            Some(b'-' | b'0'..=b'9') => self.parse_number(),
            _ => Err(self.invalid()),
        }
    }

    fn parse_literal(
        &mut self,
        expected: &[u8],
        value: CapturedValue,
    ) -> Result<CapturedValue, IntegrityError> {
        if self.bytes.get(self.index..self.index + expected.len()) == Some(expected) {
            self.index += expected.len();
            Ok(value)
        } else {
            Err(self.invalid())
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<CapturedValue, IntegrityError> {
        self.index += 1;
        self.skip_whitespace();
        let mut values = Vec::new();
        if self.consume(b']') {
            return Ok(CapturedValue::Array(values));
        }
        loop {
            values.push(self.parse_value(depth)?);
            self.skip_whitespace();
            if self.consume(b']') {
                return Ok(CapturedValue::Array(values));
            }
            if !self.consume(b',') {
                return Err(self.invalid());
            }
            self.skip_whitespace();
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<CapturedValue, IntegrityError> {
        self.index += 1;
        self.skip_whitespace();
        let mut entries = Vec::new();
        let mut seen = HashSet::new();
        if self.consume(b'}') {
            return Ok(CapturedValue::Object(entries));
        }
        loop {
            if self.peek() != Some(b'"') {
                return Err(self.invalid());
            }
            let key = self.parse_string()?;
            if !seen.insert(key.clone()) {
                let (line, column) = self.position();
                return Err(IntegrityError::DuplicateKey { line, column });
            }
            self.skip_whitespace();
            if !self.consume(b':') {
                return Err(self.invalid());
            }
            let value = self.parse_value(depth)?;
            entries.push((key, value));
            self.skip_whitespace();
            if self.consume(b'}') {
                return Ok(CapturedValue::Object(entries));
            }
            if !self.consume(b',') {
                return Err(self.invalid());
            }
            self.skip_whitespace();
        }
    }

    fn parse_string(&mut self) -> Result<String, IntegrityError> {
        let start = self.index;
        self.index += 1;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.index += 1;
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' => escaped = true,
                b'"' => {
                    let raw = &self.input[start..self.index];
                    if raw.len() > MAX_STRING_BYTES {
                        return Err(self.invalid());
                    }
                    return serde_json::from_str(raw).map_err(|_| self.invalid());
                }
                _ => {}
            }
        }
        Err(self.invalid())
    }

    fn parse_number(&mut self) -> Result<CapturedValue, IntegrityError> {
        let start = self.index;
        self.consume(b'-');
        match self.peek() {
            Some(b'0') => {
                self.index += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.invalid());
                }
            }
            Some(b'1'..=b'9') => self.consume_digits(),
            _ => return Err(self.invalid()),
        }

        if self.consume(b'.') {
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.invalid());
            }
            self.consume_digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.invalid());
            }
            self.consume_digits();
        }

        let lexeme = &self.input[start..self.index];
        if lexeme.len() > MAX_NUMBER_BYTES {
            return Err(IntegrityError::Canonicalization);
        }
        parse_json_number(lexeme, self.profile).map(CapturedValue::Number)
    }

    fn consume_digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.index += 1;
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.index += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn invalid(&self) -> IntegrityError {
        let (line, column) = self.position();
        IntegrityError::InvalidJson { line, column }
    }

    fn position(&self) -> (usize, usize) {
        let prefix = &self.input[..self.index.min(self.input.len())];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = prefix
            .rsplit_once('\n')
            .map_or(prefix.chars().count() + 1, |(_, tail)| {
                tail.chars().count() + 1
            });
        (line, column)
    }
}
