use serde_json::Error as SerdeError;
use openssl::ssl::error::SslError;
use hyper::Error as HttpError;
use std::time;
use std::io;
use super::types::GcpErrors;

#[derive(Debug)]
pub enum Error {
    GCP(GcpErrors),
    JSON(SerdeError),
    PrivateKey(SslError),
    HTTP(HttpError),
    IO(io::Error),
    Time(time::SystemTimeError)
}

impl From<SerdeError> for Error {
    fn from(err: SerdeError) -> Error {
        Error::JSON(err)
    }
}

impl From<SslError> for Error {
    fn from(err: SslError) -> Error {
        Error::PrivateKey(err)
    }
}

impl From<HttpError> for Error {
    fn from(err: HttpError) -> Error {
        Error::HTTP(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<time::SystemTimeError> for Error {
    fn from(err: time::SystemTimeError) -> Error {
        Error::Time(err)
    }
}
