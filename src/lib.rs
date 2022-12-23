// Copyright (C) Nicolas Lamirault <nicolas.lamirault@gmail.com>
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
//
// SPDX-License-Identifier: Apache-2.0

use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::apps::v1 as apps;
use k8s_openapi::api::batch::v1 as batch;
use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

use slog::{info, o, warn, Logger};

const DEFAULT_NAMESPACE: &str = "default";

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "default-namespace-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn check_daemonset(obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<apps::DaemonSet>(obj) {
        Ok(daemonset) => {
            let namespace_name: String = daemonset.metadata.namespace.unwrap();
            if namespace_name == DEFAULT_NAMESPACE {
                info!(
                    LOG_DRAIN,
                    "rejecting daemonset";
                    "daemonset_namespace" => &namespace_name
                );
                return kubewarden::reject_request(
                    Some(format!(
                        "daemonset namespace {} is not accepted",
                        &namespace_name
                    )),
                    None,
                    None,
                    None,
                );
            }
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn check_deployment(obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<apps::Deployment>(obj) {
        Ok(deployment) => {
            let namespace_name: String = deployment.metadata.namespace.unwrap();
            if namespace_name == DEFAULT_NAMESPACE {
                info!(
                    LOG_DRAIN,
                    "rejecting deployment";
                    "deployment_namespace" => &namespace_name
                );
                return kubewarden::reject_request(
                    Some(format!(
                        "deployment namespace {} is not accepted",
                        &namespace_name
                    )),
                    None,
                    None,
                    None,
                );
            }
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn check_statefulset(obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<apps::StatefulSet>(obj) {
        Ok(statefulset) => {
            let namespace_name: String = statefulset.metadata.namespace.unwrap();
            if namespace_name == DEFAULT_NAMESPACE {
                info!(
                    LOG_DRAIN,
                    "rejecting statefulset";
                    "statefulset_namespace" => &namespace_name
                );
                return kubewarden::reject_request(
                    Some(format!(
                        "statefulset namespace {} is not accepted",
                        &namespace_name
                    )),
                    None,
                    None,
                    None,
                );
            }
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn check_pod(obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<apicore::Pod>(obj) {
        Ok(pod) => {
            let namespace_name: String = pod.metadata.namespace.unwrap();
            if namespace_name == DEFAULT_NAMESPACE {
                info!(
                    LOG_DRAIN,
                    "rejecting pod";
                    "pod_namespace" => &namespace_name
                );
                return kubewarden::reject_request(
                    Some(format!("pod namespace {} is not accepted", &namespace_name)),
                    None,
                    None,
                    None,
                );
            }
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn check_job(obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<batch::Job>(obj) {
        Ok(job) => {
            let namespace_name: String = job.metadata.namespace.unwrap();
            if namespace_name == DEFAULT_NAMESPACE {
                info!(
                    LOG_DRAIN,
                    "rejecting job";
                    "job_namespace" => &namespace_name
                );
                return kubewarden::reject_request(
                    Some(format!("job namespace {} is not accepted", &namespace_name)),
                    None,
                    None,
                    None,
                );
            }
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn check_cronjob(obj: serde_json::Value) -> CallResult {
    match serde_json::from_value::<batch::CronJob>(obj) {
        Ok(cronjob) => {
            let namespace_name: String = cronjob.metadata.namespace.unwrap();
            if namespace_name == DEFAULT_NAMESPACE {
                info!(
                    LOG_DRAIN,
                    "rejecting cronjob";
                    "cronjob_namespace" => &namespace_name
                );
                return kubewarden::reject_request(
                    Some(format!(
                        "cronjob namespace {} is not accepted",
                        &namespace_name
                    )),
                    None,
                    None,
                    None,
                );
            }
            kubewarden::accept_request()
        }
        Err(_) => {
            warn!(LOG_DRAIN, "cannot unmarshal resource: this policy does not know how to evaluate this resource; accept it");
            kubewarden::accept_request()
        }
    }
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    info!(LOG_DRAIN, "starting validation");

    let kind: String = validation_request.request.kind.kind;

    return match kind.as_ref() {
        "DaemonSet" => check_daemonset(validation_request.request.object),
        "Deployment" => check_deployment(validation_request.request.object),
        "StatefulSet" => check_statefulset(validation_request.request.object),
        "Pod" => check_pod(validation_request.request.object),
        "Job" => check_job(validation_request.request.object),
        "CronJob" => check_cronjob(validation_request.request.object),
        _ => kubewarden::accept_request(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::test::Testcase;

    #[test]
    fn accept_pod_with_valid_namespace() -> Result<(), ()> {
        let request_file = "test_data/pod_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_pod_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_namespace.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_deployment_with_valid_namespace() -> Result<(), ()> {
        let request_file = "test_data/deployment_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_deployment_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/deployment_creation_invalid_namespace.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_statefulset_with_valid_namespace() -> Result<(), ()> {
        let request_file = "test_data/statefulset_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_statefulset_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/statefulset_creation_invalid_namespace.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn accept_daemonset_with_valid_namespace() -> Result<(), ()> {
        let request_file = "test_data/daemonset_creation.json";
        let tc = Testcase {
            name: String::from("Valid name"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }

    #[test]
    fn reject_daemonset_with_invalid_namespace() -> Result<(), ()> {
        let request_file = "test_data/daemonset_creation_invalid_namespace.json";
        let tc = Testcase {
            name: String::from("Bad name"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {},
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Something mutated with test case: {}",
            tc.name,
        );

        Ok(())
    }
}
