// SPDX-License-Identifier: MIT OR Apache-2.0
//
// This file is licensed under the MIT license or the Apache License, Version 2.0, at your choice.
//
// Copyright 2016 Fedor Gogolev
// Copyright 2025 Oliver Old
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ffi::CString;
use std::io::{Read, Write, stdin};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use bincode::{Decode, Encode};

use crate::{Daemonize, Error, Group, Mask, Outcome, User};

pub const STDOUT_DATA: &str = "stdout data";
pub const STDERR_DATA: &str = "stderr data";
pub const ADDITIONAL_FILE_DATA: &str = "additional file data";
pub const USER_NAME: &str = "daemonize-test";
pub const GROUP_NAME: &str = "daemonize-test";

const TESTER_PATH: &str = "target/debug/examples/tester";

const MAX_WAIT_DURATION: Duration = Duration::from_secs(5);

const BINCODE_CONFIG: bincode::config::Configuration = bincode::config::standard();

#[derive(Encode, Decode, Default)]
pub struct TesterConfig {
    pid_file: Option<PathBuf>,
    chown_pid_file_user: Option<User>,
    chown_pid_file_group: Option<Group>,
    working_directory: Option<PathBuf>,
    user: Option<User>,
    group: Option<Group>,
    umask: Option<Mask>,
    chroot: Option<PathBuf>,
    stdout: Option<PathBuf>,
    stderr: Option<PathBuf>,
    additional_files: Vec<PathBuf>,
    additional_files_privileged: Vec<PathBuf>,
    sleep_duration: Option<Duration>,
}

impl TesterConfig {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn pid_file<F: Into<PathBuf>>(&mut self, pid_file: F) -> &mut Self {
        self.pid_file = Some(pid_file.into());
        self
    }

    pub fn chown_pid_file_user<U: Into<User>>(&mut self, user: U) -> &mut Self {
        self.chown_pid_file_user = Some(user.into());
        self
    }

    pub fn chown_pid_file_group<G: Into<Group>>(&mut self, group: G) -> &mut Self {
        self.chown_pid_file_group = Some(group.into());
        self
    }

    pub fn working_directory<F: Into<PathBuf>>(&mut self, path: F) -> &mut Self {
        self.working_directory = Some(path.into());
        self
    }

    pub fn user<U: Into<User>>(&mut self, user: U) -> &mut Self {
        self.user = Some(user.into());
        self
    }

    pub fn group<G: Into<Group>>(&mut self, group: G) -> &mut Self {
        self.group = Some(group.into());
        self
    }

    pub fn umask<M: Into<Mask>>(&mut self, umask: M) -> &mut Self {
        self.umask = Some(umask.into());
        self
    }

    pub fn chroot<F: Into<PathBuf>>(&mut self, path: F) -> &mut Self {
        self.chroot = Some(path.into());
        self
    }

    pub fn stdout<F: Into<PathBuf>>(&mut self, path: F) -> &mut Self {
        self.stdout = Some(path.into());
        self
    }

    pub fn stderr<F: Into<PathBuf>>(&mut self, path: F) -> &mut Self {
        self.stderr = Some(path.into());
        self
    }

    pub fn additional_file<F: Into<PathBuf>>(&mut self, path: F) -> &mut Self {
        self.additional_files.push(path.into());
        self
    }

    pub fn additional_file_privileged<F: Into<PathBuf>>(&mut self, path: F) -> &mut Self {
        self.additional_files_privileged.push(path.into());
        self
    }

    pub fn sleep(&mut self, duration: Duration) -> &mut Self {
        self.sleep_duration = Some(duration);
        self
    }

    pub fn run(&self) -> Result<EnvData, Error> {
        let mut child = Command::new(TESTER_PATH)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("unable to spawn child");

        bincode::encode_into_std_write(self, &mut child.stdin.take().unwrap(), BINCODE_CONFIG)
            .expect("failed to encode config");

        let st = Instant::now();

        let exit_status = loop {
            let now = Instant::now();
            if now - st > MAX_WAIT_DURATION {
                panic!("wait for result timeout")
            }
            match child.try_wait().expect("unable to wait for result") {
                Some(result) => break result,
                None => sleep(Duration::from_millis(1)),
            }
        };

        if !exit_status.success() {
            let mut stderr = String::new();
            child
                .stderr
                .expect("unable to get stderr")
                .read_to_string(&mut stderr)
                .expect("unable to read tester stderr");
            panic!(
                "invalid tester exit status ({}), stderr: {}",
                exit_status.code().expect("unable to get status code"),
                stderr
            );
        }

        let mut stdout = child.stdout.expect("unable to get stdout");
        bincode::decode_from_std_read(&mut stdout, BINCODE_CONFIG)
            .expect("unable to read tester stdout")
    }
}

#[derive(Debug, Encode, Decode)]
pub struct EnvData {
    pub cwd: PathBuf,
    pub pid: u32,
    pub euid: u32,
    pub egid: u32,
}

impl EnvData {
    fn new() -> EnvData {
        Self {
            cwd: std::env::current_dir().expect("unable to get current dir"),
            pid: std::process::id(),
            euid: unsafe { libc::geteuid() as u32 },
            egid: unsafe { libc::getegid() as u32 },
        }
    }
}

pub fn execute_tester() {
    let mut daemonize = Daemonize::new();
    let config: TesterConfig = bincode::decode_from_std_read(&mut stdin(), BINCODE_CONFIG)
        .expect("failed to decode config");

    if let Some(f) = config.pid_file {
        daemonize = daemonize.pid_file(f);
    }

    if let Some(u) = config.chown_pid_file_user {
        daemonize = daemonize.chown_pid_file_user(u);
    }

    if let Some(g) = config.chown_pid_file_group {
        daemonize = daemonize.chown_pid_file_group(g);
    }

    if let Some(wd) = config.working_directory {
        daemonize = daemonize.working_directory(wd);
    }

    if let Some(u) = config.user {
        daemonize = daemonize.user(u);
    }

    if let Some(g) = config.group {
        daemonize = daemonize.group(g);
    }

    if let Some(m) = config.umask {
        daemonize = daemonize.umask(m);
    }

    if let Some(chroot) = config.chroot {
        daemonize = daemonize.chroot(chroot);
    }

    let mut redirected_stdout = false;
    if let Some(stdout) = config.stdout {
        let file = std::fs::File::create(stdout).expect("unable to open stdout file");
        daemonize = daemonize.stdout(file);
        redirected_stdout = true;
    }

    let mut redirected_stderr = false;
    if let Some(stderr) = config.stderr {
        let file = std::fs::File::create(stderr).expect("unable to open stder file");
        daemonize = daemonize.stderr(file);
        redirected_stderr = true;
    }

    daemonize = daemonize.privileged_action(move || {
        for file_path in config.additional_files_privileged {
            if let Ok(mut file) = std::fs::File::create(file_path) {
                file.write_all(ADDITIONAL_FILE_DATA.as_bytes()).ok();
            }
        }
    });

    let (mut read_pipe, mut write_pipe) = os_pipe::pipe().expect("unable to open pipe");

    match unsafe { daemonize.execute() } {
        Outcome::Parent(_) => {
            drop(write_pipe);
            let mut data = Vec::new();
            read_pipe
                .read_to_end(&mut data)
                .expect("unable to read pipe");
            std::io::stdout()
                .write_all(&data)
                .expect("unable to write data")
        }
        Outcome::Child(result) => {
            drop(read_pipe);
            let result = result.map(|_| EnvData::new());

            if redirected_stdout {
                print!("{}", STDOUT_DATA);
            }

            if redirected_stderr {
                eprint!("{}", STDERR_DATA);
            }

            for file_path in config.additional_files {
                if let Ok(mut file) = std::fs::File::create(file_path) {
                    let _ = file.write_all(ADDITIONAL_FILE_DATA.as_bytes());
                }
            }

            bincode::encode_into_std_write(result, &mut write_pipe, BINCODE_CONFIG)
                .expect("failed to write bincoded result");

            drop(write_pipe);

            if let Some(duration) = config.sleep_duration {
                std::thread::sleep(duration)
            }
        }
    }
}

pub fn get_test_uid() -> u32 {
    let name = CString::new(USER_NAME).unwrap();
    unsafe {
        let ptr = libc::getpwnam(name.as_ptr() as *const libc::c_char);
        if ptr.is_null() {
            panic!("getpwnam failed")
        } else {
            let s = &*ptr;
            s.pw_uid
        }
    }
}

pub fn get_test_gid() -> u32 {
    let name = CString::new(GROUP_NAME).unwrap();
    unsafe {
        let ptr = libc::getgrnam(name.as_ptr() as *const libc::c_char);
        if ptr.is_null() {
            panic!("getgrnam failed")
        } else {
            let s = &*ptr;
            s.gr_gid
        }
    }
}
