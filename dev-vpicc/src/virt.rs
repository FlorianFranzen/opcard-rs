// Copyright (C) 2022 Nitrokey GmbH
// SPDX-License-Identifier: LGPL-3.0-only

//! Virtual trussed client (mostly for testing)

/// Implementation of ExtensionDispatch for a virtual implementation of opcard
pub mod dispatch {

    use trussed::{
        backend::{Backend as _, BackendId},
        platform::Platform,
        serde_extensions::{ExtensionDispatch, ExtensionId, ExtensionImpl},
        service::ServiceResources,
        types::Context,
    };
    use trussed_auth::AuthExtension;
    use trussed_auth_backend::{AuthBackend, AuthContext, FilesystemLayout, MAX_HW_KEY_LEN};
    use trussed_chunked::ChunkedExtension;
    use trussed_core::{
        Error,
        api::{Reply, Request, reply, request},
        types::{Bytes, Location},
    };
    use trussed_staging::{StagingBackend, StagingContext};
    use trussed_wrap_key_to_file::WrapKeyToFileExtension;

    use trussed_rsa_alloc::SoftwareRsa;

    /// Backends used by opcard
    pub const BACKENDS: &[BackendId<Backend>] = &[
        BackendId::Custom(Backend::Staging),
        BackendId::Custom(Backend::Auth),
        BackendId::Custom(Backend::Rsa),
        BackendId::Core,
    ];

    /// Id for the ExtensionDispatch implementation
    #[derive(Debug, Clone, Copy)]
    pub enum Backend {
        /// trussed-auth
        Auth,
        /// trussed-staging
        Staging,
        /// trussed-rsa-alloc
        Rsa,
    }

    /// Extensions used by opcard
    /// Used for the ExtensionDispatch implementation
    #[derive(Debug, Clone, Copy)]
    pub enum Extension {
        /// trussed-auth
        Auth,
        /// wrap_key_to_file
        WrapKeyToFile,
        /// chunked
        Chunked,
    }

    impl From<Extension> for u8 {
        fn from(extension: Extension) -> Self {
            match extension {
                Extension::Auth => 0,
                Extension::WrapKeyToFile => 1,
                Extension::Chunked => 2,
            }
        }
    }

    impl TryFrom<u8> for Extension {
        type Error = Error;

        fn try_from(id: u8) -> Result<Self, Self::Error> {
            match id {
                0 => Ok(Extension::Auth),
                1 => Ok(Extension::WrapKeyToFile),
                2 => Ok(Extension::Chunked),
                _ => Err(Error::InternalError),
            }
        }
    }

    /// Dispatch implementation with the backends required by opcard
    #[derive(Debug)]
    pub struct Dispatch {
        auth: AuthBackend,
        staging: StagingBackend,
    }

    #[allow(missing_debug_implementations)]
    /// Dispatch context for the backends required by opcard
    #[derive(Default)]
    pub struct DispatchContext {
        auth: AuthContext,
        staging: StagingContext,
    }

    impl Dispatch {
        /// Create a new dispatch using the internal filesystem
        pub fn new() -> Self {
            Self {
                auth: AuthBackend::new(Location::Internal, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }

        /// Create a new dispatch using the internal filesystem and a key derived from hardware parameters
        pub fn with_hw_key(hw_key: Bytes<MAX_HW_KEY_LEN>) -> Self {
            Self {
                auth: AuthBackend::with_hw_key(Location::Internal, hw_key, FilesystemLayout::V0),
                staging: StagingBackend::new(),
            }
        }
    }

    impl Default for Dispatch {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ExtensionDispatch for Dispatch {
        type BackendId = Backend;
        type Context = DispatchContext;
        type ExtensionId = Extension;

        fn core_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            ctx: &mut Context<Self::Context>,
            request: &Request,
            resources: &mut ServiceResources<P>,
        ) -> Result<Reply, Error> {
            match backend {
                Backend::Auth => {
                    self.auth
                        .request(&mut ctx.core, &mut ctx.backends.auth, request, resources)
                }
                Backend::Staging => self.staging.request(
                    &mut ctx.core,
                    &mut ctx.backends.staging,
                    request,
                    resources,
                ),
                Backend::Rsa => SoftwareRsa.request(&mut ctx.core, &mut (), request, resources),
            }
        }

        fn extension_request<P: Platform>(
            &mut self,
            backend: &Self::BackendId,
            extension: &Self::ExtensionId,
            ctx: &mut Context<Self::Context>,
            request: &request::SerdeExtension,
            resources: &mut ServiceResources<P>,
        ) -> Result<reply::SerdeExtension, Error> {
            match backend {
                Backend::Auth => match extension {
                    Extension::Auth => self.auth.extension_request_serialized(
                        &mut ctx.core,
                        &mut ctx.backends.auth,
                        request,
                        resources,
                    ),
                    Extension::WrapKeyToFile | Extension::Chunked => {
                        Err(Error::RequestNotAvailable)
                    }
                },
                Backend::Staging => match extension {
                    Extension::WrapKeyToFile => <StagingBackend as ExtensionImpl<
                        WrapKeyToFileExtension,
                    >>::extension_request_serialized(
                        &mut self.staging,
                        &mut ctx.core,
                        &mut ctx.backends.staging,
                        request,
                        resources,
                    ),
                    Extension::Chunked => <StagingBackend as ExtensionImpl<
                        ChunkedExtension,
                    >>::extension_request_serialized(
                        &mut self.staging,
                        &mut ctx.core,
                        &mut ctx.backends.staging,
                        request,
                        resources,
                    ),
                    Extension::Auth => Err(Error::RequestNotAvailable),
                },

                Backend::Rsa => Err(Error::RequestNotAvailable),
            }
        }
    }

    impl ExtensionId<AuthExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Auth;
    }

    impl ExtensionId<WrapKeyToFileExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::WrapKeyToFile;
    }
    impl ExtensionId<ChunkedExtension> for Dispatch {
        type Id = Extension;

        const ID: Self::Id = Self::Id::Chunked;
    }
}

use std::path::PathBuf;
use trussed::{
    pipe::TrussedChannel,
    platform::{Platform as _, UserInterface},
    virt::{self, Client, Runner, StorageConfig, StoreConfig},
};
use trussed_core::types::{Bytes, consent};

/// Names a file that decides user presence, for tests that need a touch to be refused
///
/// Unset, every presence check is granted, as before. Set, the file is read on every check:
/// `deny` refuses (the request then waits out its timeout, as on a token nobody touches),
/// anything else or a missing file grants.
pub const USER_PRESENCE_ENV: &str = "VPICC_USER_PRESENCE";

/// User presence as the file named by [`USER_PRESENCE_ENV`] says
struct FileUserPresence(PathBuf);

impl UserInterface for FileUserPresence {
    fn check_user_presence(&mut self) -> consent::Level {
        match std::fs::read_to_string(&self.0) {
            Ok(answer) if answer.trim() == "deny" => consent::Level::None,
            _ => consent::Level::Normal,
        }
    }
}

/// Hand presence checks to [`FileUserPresence`] when the environment names a file
fn control_user_presence(platform: &mut virt::Platform<'_>) {
    if let Some(path) = std::env::var_os(USER_PRESENCE_ENV) {
        platform
            .user_interface()
            .set_inner(Box::new(FileUserPresence(path.into())));
    }
}

/// Client type using a dispatcher with the backends required by opcard
pub type VirtClient<'a> = Client<'a, dispatch::Dispatch>;

/// Run a client using a provided store
pub fn with_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    virt::with_platform(store, |mut platform| {
        control_user_presence(&mut platform);
        platform.run_client_with_backends(
            client_id,
            dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes")),
            dispatch::BACKENDS,
            f,
        )
    })
}

/// Run the backend with the extensions required by opcard
/// using storage backed by a file
pub fn with_fs_client<P, R, F>(internal: P, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
    P: Into<PathBuf>,
{
    let store = StoreConfig {
        internal: StorageConfig::filesystem(internal.into()),
        external: StorageConfig::ram(),
        volatile: StorageConfig::ram(),
    };
    with_client(store, client_id, f)
}

/// Run the backend with the extensions required by opcard
/// using a RAM file storage
pub fn with_ram_client<R, F>(client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'_>) -> R,
{
    with_client(StoreConfig::ram(), client_id, f)
}

/// Run a client using a provided store, leaking the interchange to achieve static lifetime of the
/// client
pub fn with_leaking_client<R, F>(store: StoreConfig, client_id: &str, f: F) -> R
where
    F: FnOnce(VirtClient<'static>) -> R,
{
    virt::with_platform(store, |mut platform| {
        control_user_presence(&mut platform);
        let channel = Box::leak(Box::new(TrussedChannel::new()));
        let mut runner = Runner::new();
        #[expect(clippy::unwrap_used)]
        let (requester, responder) = channel.split().unwrap();
        runner.add_endpoint(responder, client_id, dispatch::BACKENDS);
        let dispatch = dispatch::Dispatch::with_hw_key(Bytes::from(b"some bytes"));
        let client = Client::new(requester, runner.syscall(), None);
        runner.run(platform, dispatch, || f(client))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_decides_user_presence() {
        let path = std::env::temp_dir().join(format!("vpicc-up-{}", std::process::id()));
        let mut presence = FileUserPresence(path.clone());
        assert_eq!(presence.check_user_presence(), consent::Level::Normal);
        std::fs::write(&path, "deny\n").unwrap();
        assert_eq!(presence.check_user_presence(), consent::Level::None);
        std::fs::write(&path, "grant").unwrap();
        assert_eq!(presence.check_user_presence(), consent::Level::Normal);
        std::fs::remove_file(&path).unwrap();
    }
}
