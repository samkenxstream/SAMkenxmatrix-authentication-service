// Copyright 2021 The Matrix.org Foundation C.I.C.
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

use oauth2_types::scope::{Scope, ScopeToken, ADDRESS, EMAIL, PHONE, PROFILE};

pub trait ScopeDisplay {
    fn detect(already_granted: &Scope, to_grant: &Scope) -> Option<Self>
    where
        Self: Sized;

    fn display_to_grant(&self) -> Option<String>;
    fn display_granted(&self) -> Option<String>;

    fn boxed(self) -> Box<dyn ScopeDisplay>
    where
        Self: Sized + 'static,
    {
        Box::new(self)
    }
}

pub fn detect_scopes(already_granted: &Scope, to_grant: &Scope) -> Vec<Box<dyn ScopeDisplay>> {
    let list = vec![UserInformations::detect(already_granted, to_grant).map(ScopeDisplay::boxed)];
    list.into_iter().flatten().collect()
}

fn find_state(already_granted: &Scope, to_grant: &Scope, what: &ScopeToken) -> ScopeState {
    let already_granted = already_granted.iter().any(|x| x == what);
    let to_grant = to_grant.iter().any(|x| x == what);
    if already_granted {
        ScopeState::Granted
    } else if to_grant {
        ScopeState::ToGrant
    } else {
        ScopeState::Missing
    }
}

#[derive(Debug, Clone, Copy)]
enum ScopeState {
    Missing,
    Granted,
    ToGrant,
}

impl ScopeState {
    /// Returns `true` if the scope state is [`Missing`].
    ///
    /// [`Missing`]: ScopeState::Missing
    fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }

    /// Returns `true` if the scope state is [`Granted`].
    ///
    /// [`Granted`]: ScopeState::Granted
    fn is_granted(self) -> bool {
        matches!(self, Self::Granted)
    }

    /// Returns `true` if the scope state is [`ToGrant`].
    ///
    /// [`ToGrant`]: ScopeState::ToGrant
    fn is_to_grant(self) -> bool {
        matches!(self, Self::ToGrant)
    }
}

pub struct UserInformations {
    profile: ScopeState,
    email: ScopeState,
    address: ScopeState,
    phone: ScopeState,
}

impl ScopeDisplay for UserInformations {
    fn detect(already_granted: &Scope, to_grant: &Scope) -> Option<Self> {
        let profile = find_state(already_granted, to_grant, &PROFILE);
        let email = find_state(already_granted, to_grant, &EMAIL);
        let address = find_state(already_granted, to_grant, &ADDRESS);
        let phone = find_state(already_granted, to_grant, &PHONE);

        if profile.is_missing() && email.is_missing() && address.is_missing() && phone.is_missing()
        {
            None
        } else {
            Some(Self {
                profile,
                email,
                address,
                phone,
            })
        }
    }

    fn display_to_grant(&self) -> Option<String> {
        let mut list = Vec::new();
        if self.profile.is_to_grant() {
            list.push("basic informations, including your full name");
        }
        if self.email.is_to_grant() {
            list.push("your email address");
        }
        if self.address.is_to_grant() {
            list.push("your postal address");
        }
        if self.phone.is_to_grant() {
            list.push("your phone number address");
        }

        let infos = match list.len() {
            0 => None,
            1 => Some(list[0].to_string()),
            len => {
                let tail = list[len - 1];
                let head = &list[0..len - 1];
                Some(format!("{} and {}", head.join(", "), tail))
            }
        };

        infos.map(|x| format!("Informations about you: {}", x))
    }

    fn display_granted(&self) -> Option<String> {
        let mut list = Vec::new();
        if self.profile.is_granted() {
            list.push("basic informations, including your full name");
        }
        if self.email.is_granted() {
            list.push("your email address");
        }
        if self.address.is_granted() {
            list.push("your postal address");
        }
        if self.phone.is_granted() {
            list.push("your phone number address");
        }

        let infos = match list.len() {
            0 => None,
            1 => Some(list[0].to_string()),
            len => {
                let tail = list[len - 1];
                let head = &list[0..len - 1];
                Some(format!("{} and {}", head.join(", "), tail))
            }
        };

        infos.map(|x| format!("Informations about you: {}", x))
    }
}
