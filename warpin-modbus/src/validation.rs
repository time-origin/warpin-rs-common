use crate::{Request, Response, Result, failure};
use warpin_errors::protocol::{Kind, Phase};
fn range(address: u16, count: usize, max: usize) -> bool {
    count > 0 && count <= max && usize::from(address) + count <= 65536
}
pub(crate) fn request(r: &Request<'_>) -> Result<bool> {
    use Request::*;
    let (valid, read) = match r {
        ReadCoils(a, n) | ReadDiscreteInputs(a, n) => (range(*a, usize::from(*n), 2000), true),
        ReadHoldingRegisters(a, n) | ReadInputRegisters(a, n) => {
            (range(*a, usize::from(*n), 125), true)
        }
        WriteSingleCoil(..) | WriteSingleRegister(..) | MaskWriteRegister(..) => (true, false),
        WriteMultipleCoils(a, v) => (range(*a, v.len(), 1968), false),
        WriteMultipleRegisters(a, v) => (range(*a, v.len(), 123), false),
        ReadWriteMultipleRegisters(a, n, b, v) => (
            range(*a, usize::from(*n), 125) && range(*b, v.len(), 121),
            false,
        ),
        _ => (false, false),
    };
    if !valid {
        return Err(failure(Kind::Configuration, Phase::Configure));
    }
    Ok(read)
}
pub(crate) fn response(q: &Request<'_>, r: &mut Response) -> bool {
    match (q, r) {
        (Request::ReadCoils(_, n), Response::ReadCoils(v))
        | (Request::ReadDiscreteInputs(_, n), Response::ReadDiscreteInputs(v)) => {
            let n = usize::from(*n);
            if v.len() != n.div_ceil(8) * 8 {
                return false;
            }
            v.truncate(n);
            true
        }
        (Request::ReadHoldingRegisters(_, n), Response::ReadHoldingRegisters(v))
        | (Request::ReadInputRegisters(_, n), Response::ReadInputRegisters(v))
        | (
            Request::ReadWriteMultipleRegisters(_, n, _, _),
            Response::ReadWriteMultipleRegisters(v),
        ) => v.len() == usize::from(*n),
        (Request::WriteSingleCoil(a, v), Response::WriteSingleCoil(b, w)) => a == b && v == w,
        (Request::WriteSingleRegister(a, v), Response::WriteSingleRegister(b, w)) => {
            a == b && v == w
        }
        (Request::WriteMultipleCoils(a, v), Response::WriteMultipleCoils(b, n)) => {
            a == b && v.len() == usize::from(*n)
        }
        (Request::WriteMultipleRegisters(a, v), Response::WriteMultipleRegisters(b, n)) => {
            a == b && v.len() == usize::from(*n)
        }
        (Request::MaskWriteRegister(a, x, y), Response::MaskWriteRegister(b, u, v)) => {
            a == b && x == u && y == v
        }
        _ => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn invalid_ranges() {
        for q in [
            Request::ReadCoils(0, 0),
            Request::ReadCoils(0, 2001),
            Request::ReadHoldingRegisters(65535, 2),
            Request::WriteMultipleRegisters(0, vec![0; 124].into()),
            Request::Custom(1, vec![].into()),
        ] {
            assert!(request(&q).is_err());
        }
        assert!(request(&Request::ReadHoldingRegisters(65535, 1)).is_ok());
    }
    #[test]
    fn echo_and_padding() {
        assert!(!response(
            &Request::WriteSingleRegister(1, 2),
            &mut Response::WriteSingleRegister(2, 2)
        ));
        let mut r = Response::ReadCoils(vec![true; 8]);
        assert!(response(&Request::ReadCoils(0, 1), &mut r));
        assert_eq!(r, Response::ReadCoils(vec![true]));
        assert!(!response(&Request::ReadCoils(0, 9), &mut r));
    }
}
