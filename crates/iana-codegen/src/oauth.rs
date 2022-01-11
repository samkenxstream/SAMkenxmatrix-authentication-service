// Copyright 2022 The Matrix.org Foundation C.I.C.
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

use serde::Deserialize;

use crate::EnumEntry;

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TokenTypeHint {
    #[serde(rename = "Hint Value")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for TokenTypeHint {
    const URL: &'static str =
        "https://www.iana.org/assignments/oauth-parameters/token-type-hint.csv";
    const SECTIONS: &'static [&'static str] = &["OAuthTokenTypeHint"];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthTokenTypeHint")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuthorizationEndpointResponseType {
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for AuthorizationEndpointResponseType {
    const URL: &'static str = "https://www.iana.org/assignments/oauth-parameters/endpoint.csv";
    const SECTIONS: &'static [&'static str] = &["OAuthAuthorizationEndpointResponseType"];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthAuthorizationEndpointResponseType")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct TokenEndpointAuthenticationMethod {
    #[serde(rename = "Token Endpoint Authentication Method Name")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for TokenEndpointAuthenticationMethod {
    const URL: &'static str =
        "https://www.iana.org/assignments/oauth-parameters/token-endpoint-auth-method.csv";
    const SECTIONS: &'static [&'static str] = &["OAuthTokenEndpointAuthenticationMethod"];

    fn key(&self) -> Option<&'static str> {
        Some("OAuthTokenEndpointAuthenticationMethod")
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PkceCodeChallengeMethod {
    #[serde(rename = "Code Challenge Method Parameter Name")]
    name: String,
    #[serde(rename = "Change Controller")]
    change_controller: String,
    #[serde(rename = "Reference")]
    reference: String,
}

impl EnumEntry for PkceCodeChallengeMethod {
    const URL: &'static str =
        "https://www.iana.org/assignments/oauth-parameters/pkce-code-challenge-method.csv";
    const SECTIONS: &'static [&'static str] = &["PkceCodeChallengeMethod"];

    fn key(&self) -> Option<&'static str> {
        Some("PkceCodeChallengeMethod")
    }

    fn name(&self) -> &str {
        &self.name
    }
}
