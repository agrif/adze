#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ParseInput<'a> {
    data: &'a [u8],
}

impl<'a> ParseInput<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn read(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            None
        } else {
            let (a, b) = self.data.split_at(n);
            self.data = b;
            Some(a)
        }
    }

    pub fn peek(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            None
        } else {
            Some(&self.data[..n])
        }
    }

    pub fn read_all(&mut self) -> &'a [u8] {
        std::mem::take(&mut self.data)
    }

    pub fn read_u8(&mut self) -> Option<u8> {
        Some(self.read(1)?[0])
    }

    pub fn peek_u8(&mut self) -> Option<u8> {
        Some(self.peek(1)?[0])
    }

    pub fn read_str(&mut self, n: usize) -> Option<&'a str> {
        std::str::from_utf8(self.read(n)?).ok()
    }

    pub fn read_all_str(&mut self) -> Option<&'a str> {
        std::str::from_utf8(self.read_all()).ok()
    }
}

pub trait Unparse {
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult;
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnparseError {
    #[error("buffer overflow, no space in output")]
    BufferOverflow,
}

pub type UnparseResult = Result<(), UnparseError>;

impl Unparse for &[u8] {
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        output.write(self)
    }
}

impl Unparse for Vec<u8> {
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        output.write(self)
    }
}

impl Unparse for &str {
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        output.write(self.as_bytes())
    }
}

impl Unparse for String {
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        output.write(self.as_bytes())
    }
}

pub trait UnparseOutput: Sized {
    fn write(&mut self, data: &[u8]) -> UnparseResult;

    fn write_unparse(&mut self, value: &impl Unparse) -> UnparseResult {
        value.unparse(self)
    }

    fn write_u8(&mut self, value: u8) -> UnparseResult {
        self.write(&[value])
    }
}

impl UnparseOutput for &mut [u8] {
    fn write(&mut self, data: &[u8]) -> UnparseResult {
        if self.len() < data.len() {
            Err(UnparseError::BufferOverflow)
        } else {
            let (dest, rest) = std::mem::take(self).split_at_mut(data.len());
            dest.copy_from_slice(data);
            *self = rest;
            Ok(())
        }
    }
}

impl UnparseOutput for Vec<u8> {
    fn write(&mut self, data: &[u8]) -> UnparseResult {
        self.extend_from_slice(data);
        Ok(())
    }
}
