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

#![cfg(all(unix, feature = "tester"))]

extern crate daemonize2;
extern crate tempfile;

use std::{
    fs::Permissions,
    os::unix::fs::{MetadataExt, PermissionsExt},
};

use daemonize2::tester_lib::{
    GROUP_NAME, STDERR_DATA, STDOUT_DATA, Tester, USER_NAME, get_test_gid, get_test_uid,
};
use tempfile::TempDir;

#[test]
fn simple() {
    let result = Tester::new().run();
    assert!(result.is_ok())
}

#[test]
fn chdir() {
    let result = Tester::new().run();
    assert_eq!(result.unwrap().cwd, std::env::current_dir().unwrap());

    let result = Tester::new().working_directory("/usr").run();
    assert_eq!(result.unwrap().cwd.as_path(), std::path::Path::new("/usr"));
}

#[test]
fn umask() {
    let tmpdir = if let Some(test_dir) = std::env::var_os("DAEMONIZE_UMASK_TEST_DIR") {
        std::fs::create_dir_all(&test_dir).expect("cannot create parent directory for umask test");
        TempDir::new_in(test_dir).unwrap()
    } else {
        TempDir::new().unwrap()
    };
    let path = tmpdir.path().join("umask-test");

    let result = Tester::new().umask(0o222).additional_file(&path).run();
    assert!(result.is_ok());
    assert!(path.metadata().unwrap().permissions().readonly());
}

#[test]
fn pid() {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("pid");

    let result = Tester::new()
        .pid_file(&path)
        .sleep(std::time::Duration::from_secs(5))
        .run();
    let pid_content = std::fs::read_to_string(&path).unwrap();
    assert!(pid_content.ends_with('\n'));
    let pid = pid_content[..pid_content.len() - 1].parse().unwrap();
    assert_eq!(result.unwrap().pid, pid);

    let result = Tester::new().pid_file(&path).run();
    assert!(result.is_err());
}

#[test]
fn redirect_stream() {
    let tmpdir = TempDir::new().unwrap();
    let stdout = tmpdir.path().join("stdout");
    let stderr = tmpdir.path().join("stderr");

    Tester::new().stdout(&stdout).stderr(&stderr).run().unwrap();

    assert_eq!(&std::fs::read_to_string(&stdout).unwrap(), STDOUT_DATA);
    assert_eq!(&std::fs::read_to_string(&stderr).unwrap(), STDERR_DATA);

    std::fs::remove_file(&stdout).unwrap();
    std::fs::remove_file(&stderr).unwrap();

    Tester::new().stdout(&stdout).run().unwrap();
    assert_eq!(&std::fs::read_to_string(&stdout).unwrap(), STDOUT_DATA);
    assert_eq!(
        std::fs::metadata(&stderr).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );

    std::fs::remove_file(&stdout).unwrap();

    Tester::new().stderr(&stderr).run().unwrap();
    assert_eq!(
        std::fs::metadata(&stdout).unwrap_err().kind(),
        std::io::ErrorKind::NotFound
    );
    assert_eq!(&std::fs::read_to_string(&stderr).unwrap(), STDERR_DATA);
}

#[test]
fn change_uid() {
    let data = Tester::new().user_string(USER_NAME).run().unwrap();
    assert_eq!(data.euid, get_test_uid())
}

#[test]
fn change_gid() {
    let data = Tester::new().group_string(GROUP_NAME).run().unwrap();
    assert_eq!(data.egid, get_test_gid())
}

#[test]
fn chown_pid_file_user() {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("pid");

    let result = Tester::new()
        .pid_file(&path)
        .chown_pid_file_user_string(USER_NAME)
        .run();
    let pid_content = std::fs::read_to_string(&path).unwrap();
    assert!(pid_content.ends_with('\n'));
    let pid = pid_content[..pid_content.len() - 1].parse().unwrap();
    assert_eq!(result.unwrap().pid, pid);

    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.uid(), get_test_uid());
}

#[test]
fn chown_pid_file_group() {
    let tmpdir = TempDir::new().unwrap();
    let path = tmpdir.path().join("pid");

    let result = Tester::new()
        .pid_file(&path)
        .chown_pid_file_group_string(GROUP_NAME)
        .run();
    let pid_content = std::fs::read_to_string(&path).unwrap();
    assert!(pid_content.ends_with('\n'));
    let pid = pid_content[..pid_content.len() - 1].parse().unwrap();
    assert_eq!(result.unwrap().pid, pid);

    let meta = std::fs::metadata(&path).unwrap();
    assert_eq!(meta.gid(), get_test_gid());
}

#[test]
fn chroot() {
    let tmpdir = TempDir::new().unwrap();
    let path = "/a";

    Tester::new()
        .working_directory(&tmpdir)
        .chroot(&tmpdir)
        .additional_file(path)
        .run()
        .unwrap();

    assert!(std::fs::exists(tmpdir.path().join("a")).unwrap());
}

#[test]
fn privileged_action() {
    let tmpdir = tempfile::Builder::new()
        .permissions(Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let path = tmpdir.path().join("a");

    Tester::new()
        .user_string(USER_NAME)
        .group_string(GROUP_NAME)
        .additional_file(&path)
        .run()
        .unwrap();

    assert!(!std::fs::exists(&path).unwrap());

    Tester::new()
        .user_string(USER_NAME)
        .group_string(GROUP_NAME)
        .additional_file_privileged(&path)
        .run()
        .unwrap();

    assert!(std::fs::exists(&path).unwrap());
}
