use super::service::AuthService;
use std::collections::HashMap;
use zbus::{
    fdo,
    message::{Header, Message},
    names::{InterfaceName, MemberName},
    object_server::{DispatchResult2, Interface, SignalEmitter},
    zvariant::{OwnedValue, Value},
    Connection, ObjectServer,
};

// zbus 5.19's generated zero-input dispatch does not deserialize the body.
// Every Auth1 method has one exact signature: reject any other body before the
// generated handler is reached, so no admission, state or counter is touched.
// All normal dispatch and introspection remain generated. zvariant renders a
// multi-argument body signature in parentheses, so two strings are "(ss)".
pub(super) struct CheckedAuth(pub(super) AuthService);

const METHOD_SIGNATURES: [(&str, &str); 9] = [
    ("VerifyPassword", "s"),
    ("ConsumePairing", "(ss)"),
    ("ConfirmRecoveryKey", "s"),
    ("RecoverPassword", "(ss)"),
    ("EnsurePendingPairing", ""),
    ("CancelPendingPairing", ""),
    ("ResetEnrollment", ""),
    ("GetPendingPairing", ""),
    ("GetEnrollmentState", ""),
];

fn has_unexpected_arguments(member: &str, msg: &Message) -> bool {
    let Some((_, expected)) = METHOD_SIGNATURES.iter().find(|(name, _)| *name == member) else {
        return false;
    };
    let body = msg.body();
    if expected.is_empty() {
        body.signature() != &zbus::zvariant::Signature::Unit || !body.is_empty()
    } else {
        body.signature().to_string() != *expected
    }
}

#[zbus::export::async_trait::async_trait]
impl Interface for CheckedAuth {
    fn name() -> InterfaceName<'static> {
        AuthService::name()
    }

    async fn get(
        &self,
        property_name: &str,
        server: &ObjectServer,
        connection: &Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<fdo::Result<OwnedValue>> {
        self.0
            .get(property_name, server, connection, header, emitter)
            .await
    }

    async fn get_all(
        &self,
        server: &ObjectServer,
        connection: &Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> fdo::Result<HashMap<String, OwnedValue>> {
        self.0.get_all(server, connection, header, emitter).await
    }

    fn set<'call>(
        &'call self,
        property_name: &'call str,
        value: &'call Value<'_>,
        server: &'call ObjectServer,
        connection: &'call Connection,
        header: Option<&'call Header<'_>>,
        emitter: &'call SignalEmitter<'_>,
    ) -> DispatchResult2<'call> {
        self.0
            .set(property_name, value, server, connection, header, emitter)
    }

    async fn set_mut(
        &mut self,
        property_name: &str,
        value: &Value<'_>,
        server: &ObjectServer,
        connection: &Connection,
        header: Option<&Header<'_>>,
        emitter: &SignalEmitter<'_>,
    ) -> Option<fdo::Result<()>> {
        self.0
            .set_mut(property_name, value, server, connection, header, emitter)
            .await
    }

    fn call<'call>(
        &'call self,
        server: &'call ObjectServer,
        connection: &'call Connection,
        msg: &'call Message,
        name: MemberName<'call>,
    ) -> DispatchResult2<'call> {
        if has_unexpected_arguments(name.as_str(), msg) {
            let method = name.as_str().to_owned();
            return DispatchResult2::new_async(connection, msg, async move {
                Err::<String, _>(fdo::Error::InvalidArgs(format!(
                    "{method} called with the wrong signature"
                )))
            });
        }
        self.0.call(server, connection, msg, name)
    }

    fn call_mut<'call>(
        &'call mut self,
        server: &'call ObjectServer,
        connection: &'call Connection,
        msg: &'call Message,
        name: MemberName<'call>,
    ) -> DispatchResult2<'call> {
        self.0.call_mut(server, connection, msg, name)
    }

    fn introspect_to_writer(&self, writer: &mut dyn std::fmt::Write, level: usize) {
        self.0.introspect_to_writer(writer, level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! method_call {
        ($member:expr, $body:expr) => {
            Message::method_call(crate::PATH, $member)
                .unwrap()
                .interface(crate::INTERFACE)
                .unwrap()
                .build($body)
                .unwrap()
        };
    }

    #[test]
    fn every_frozen_method_has_one_exact_signature() {
        let members: Vec<&str> = METHOD_SIGNATURES.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            members,
            [
                "VerifyPassword",
                "ConsumePairing",
                "ConfirmRecoveryKey",
                "RecoverPassword",
                "EnsurePendingPairing",
                "CancelPendingPairing",
                "ResetEnrollment",
                "GetPendingPairing",
                "GetEnrollmentState"
            ]
        );
    }

    #[test]
    fn zero_argument_methods_accept_only_an_empty_body() {
        for (member, _) in METHOD_SIGNATURES.iter().filter(|(_, sig)| sig.is_empty()) {
            assert!(!has_unexpected_arguments(
                member,
                &method_call!(*member, &())
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(*member, &(0u32,))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(*member, &("x",))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(*member, &("x", "y"))
            ));
        }
    }

    #[test]
    fn one_string_methods_accept_exactly_one_string() {
        for member in ["VerifyPassword", "ConfirmRecoveryKey"] {
            assert!(!has_unexpected_arguments(
                member,
                &method_call!(member, &("x",))
            ));
            assert!(has_unexpected_arguments(member, &method_call!(member, &())));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("x", "y"))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &(1u32,))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("x", 1u32))
            ));
        }
    }

    #[test]
    fn two_string_methods_accept_exactly_two_strings() {
        for member in ["ConsumePairing", "RecoverPassword"] {
            assert!(!has_unexpected_arguments(
                member,
                &method_call!(member, &("x", "y"))
            ));
            assert!(has_unexpected_arguments(member, &method_call!(member, &())));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("x",))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("x", "y", "z"))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("x", 1u32))
            ));
        }
    }

    #[test]
    fn other_members_are_left_to_generated_dispatch() {
        assert!(!has_unexpected_arguments(
            "Introspect",
            &method_call!("Introspect", &(0u32,))
        ));
    }
}
