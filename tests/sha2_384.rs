use std::fs::{read_dir, File};
use std::io::Error as IoError;

use assert_fs::fixture::FixtureError;
use assert_fs::prelude::{FileTouch, FileWriteBin, PathChild};
use assert_fs::TempDir;
#[cfg(feature = "async-runtime-tokio")]
use chksum_sha2_384::async_chksum;
use chksum_sha2_384::{chksum, Error as ChksumError};
#[cfg(feature = "async-runtime-tokio")]
use tokio::fs::{read_dir as tokio_read_dir, File as TokioFile};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error(transparent)]
    ChksumError(#[from] ChksumError),
    #[error(transparent)]
    FixtureError(#[from] FixtureError),
    #[error(transparent)]
    IoError(#[from] IoError),
}

#[test]
fn empty_directory_as_path() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;

    let dir = temp_dir.path();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_empty_directory_as_path() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;

        let dir = temp_dir.path();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn empty_directory_as_pathbuf() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;

    let dir = temp_dir.to_path_buf();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let dir = &temp_dir.to_path_buf();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_empty_directory_as_pathbuf() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;

        let dir = temp_dir.to_path_buf();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let dir = &temp_dir.to_path_buf();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn empty_directory_as_readdir() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;

    let dir = read_dir(temp_dir.path())?;
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_empty_directory_as_readdir() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;

        let dir = tokio_read_dir(temp_dir.path()).await?;
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn non_empty_directory_with_empty_file_as_path() -> Result<(), Error> {
    let temp_dir = {
        let temp_dir = TempDir::new()?;
        temp_dir.child("file.txt").touch()?;
        temp_dir
    };

    let dir = temp_dir.path();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_directory_with_empty_file_as_path() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = {
            let temp_dir = TempDir::new()?;
            temp_dir.child("file.txt").touch()?;
            temp_dir
        };

        let dir = temp_dir.path();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn non_empty_directory_with_empty_file_as_pathbuf() -> Result<(), Error> {
    let temp_dir = {
        let temp_dir = TempDir::new()?;
        temp_dir.child("file.txt").touch()?;
        temp_dir
    };

    let dir = temp_dir.to_path_buf();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let dir = &temp_dir.to_path_buf();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_directory_with_empty_file_as_pathbuf() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = {
            let temp_dir = TempDir::new()?;
            temp_dir.child("file.txt").touch()?;
            temp_dir
        };

        let dir = temp_dir.to_path_buf();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let dir = &temp_dir.to_path_buf();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn non_empty_directory_with_empty_file_as_readdir() -> Result<(), Error> {
    let temp_dir = {
        let temp_dir = TempDir::new()?;
        temp_dir.child("file.txt").touch()?;
        temp_dir
    };

    let dir = read_dir(temp_dir.path())?;
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_directory_with_empty_file_as_readdir() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = {
            let temp_dir = TempDir::new()?;
            temp_dir.child("file.txt").touch()?;
            temp_dir
        };

        let dir = tokio_read_dir(temp_dir.path()).await?;
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn non_empty_directory_with_non_empty_file_as_path() -> Result<(), Error> {
    let temp_dir = {
        let temp_dir = TempDir::new()?;
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file.write_binary(b"data")?;
        temp_dir
    };

    let dir = temp_dir.path();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_directory_with_non_empty_file_as_path() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = {
            let temp_dir = TempDir::new()?;
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file.write_binary(b"data")?;
            temp_dir
        };

        let dir = temp_dir.path();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    Ok(())
}

#[test]
fn non_empty_directory_with_non_empty_file_as_pathbuf() -> Result<(), Error> {
    let temp_dir = {
        let temp_dir = TempDir::new()?;
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file.write_binary(b"data")?;
        temp_dir
    };

    let dir = temp_dir.to_path_buf();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    let dir = &temp_dir.to_path_buf();
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_directory_with_non_empty_file_as_pathbuf() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = {
            let temp_dir = TempDir::new()?;
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file.write_binary(b"data")?;
            temp_dir
        };

        let dir = temp_dir.to_path_buf();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let dir = &temp_dir.to_path_buf();
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    Ok(())
}

#[test]
fn non_empty_directory_with_non_empty_file_as_readdir() -> Result<(), Error> {
    let temp_dir = {
        let temp_dir = TempDir::new()?;
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file.write_binary(b"data")?;
        temp_dir
    };

    let dir = read_dir(temp_dir.path())?;
    let digest = chksum(dir)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_directory_with_non_empty_file_as_readdir() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = {
            let temp_dir = TempDir::new()?;
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file.write_binary(b"data")?;
            temp_dir
        };

        let dir = tokio_read_dir(temp_dir.path()).await?;
        let digest = async_chksum(dir).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    Ok(())
}

#[test]
fn empty_file_as_path() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;
    let child = {
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file
    };

    let file = child.path();
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_empty_file_as_path() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;
        let child = {
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file
        };

        let file = child.path();
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn empty_file_as_pathbuf() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;
    let child = {
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file
    };

    let file = child.to_path_buf();
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let file = &child.to_path_buf();
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_empty_file_as_pathbuf() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;
        let child = {
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file
        };

        let file = child.to_path_buf();
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        let file = &child.to_path_buf();
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );
    }

    Ok(())
}

#[test]
fn empty_file_as_file() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;
    let child = {
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file
    };

    let file = File::open(child.path())?;
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    let file = &File::open(child.path())?;
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_empty_file_as_file() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;
        let child = {
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file
        };

        let file = TokioFile::open(child.path()).await?;
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
        );

        // TODO: missing `&File` implementation
        // let file = &TokioFile::open(child.path()).await?;
        // let digest = async_chksum(file).await?.to_hex_lowercase();
        // assert_eq!(digest, "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    }

    Ok(())
}

#[test]
fn non_empty_file_as_path() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;
    let child = {
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file.write_binary(b"data")?;
        file
    };

    let file = child.path();
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_file_as_path() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;
        let child = {
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file.write_binary(b"data")?;
            file
        };

        let file = child.path();
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    Ok(())
}

#[test]
fn non_empty_file_as_pathbuf() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;
    let child = {
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file.write_binary(b"data")?;
        file
    };

    let file = child.to_path_buf();
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    let file = &child.to_path_buf();
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_file_as_pathbuf() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;
        let child = {
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file.write_binary(b"data")?;
            file
        };

        let file = child.to_path_buf();
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        let file = &child.to_path_buf();
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );
    }

    Ok(())
}

#[test]
fn non_empty_file_as_file() -> Result<(), Error> {
    let temp_dir = TempDir::new()?;
    let child = {
        let file = temp_dir.child("file.txt");
        file.touch()?;
        file.write_binary(b"data")?;
        file
    };

    let file = File::open(child.path())?;
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    let file = &File::open(child.path())?;
    let digest = chksum(file)?.to_hex_lowercase();
    assert_eq!(
        digest,
        "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
    );

    Ok(())
}

#[cfg_attr(not(feature = "async-runtime-tokio"), ignore)]
#[tokio::test]
async fn async_runtime_tokio_non_empty_file_as_file() -> Result<(), Error> {
    #[cfg(feature = "async-runtime-tokio")]
    {
        let temp_dir = TempDir::new()?;
        let child = {
            let file = temp_dir.child("file.txt");
            file.touch()?;
            file.write_binary(b"data")?;
            file
        };

        let file = TokioFile::open(child.path()).await?;
        let digest = async_chksum(file).await?.to_hex_lowercase();
        assert_eq!(
            digest,
            "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41"
        );

        // TODO: missing `&File` implementation
        // let file = &TokioFile::open(child.path()).await?;
        // let digest = async_chksum(file).await?.to_hex_lowercase();
        // assert_eq!(digest, "2039e0f0b92728499fb88e23ebc3cfd0554b28400b0ed7b753055c88b5865c3c2aa72c6a1a9ae0a755d87900a4a6ff41");
    }

    Ok(())
}
