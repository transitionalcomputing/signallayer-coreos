use super::Platform;
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
// Reject unexpected arguments before the generated handler acquires its permit
// or starts bootc or the reboot worker. All normal dispatch and introspection
// remain generated.
pub(super) struct CheckedPlatform(pub(super) Platform);

const ZERO_ARGUMENT_METHODS: [&str; 4] =
    ["GetStatus", "StartUpdate", "StartRollback", "StartReboot"];

fn has_unexpected_arguments(member: &str, msg: &Message) -> bool {
    ZERO_ARGUMENT_METHODS.contains(&member)
        && (msg.body().signature() != &zbus::zvariant::Signature::Unit || !msg.body().is_empty())
}

#[zbus::export::async_trait::async_trait]
impl Interface for CheckedPlatform {
    fn name() -> InterfaceName<'static> {
        Platform::name()
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
                    "{method} takes no arguments"
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
            Message::method_call(sl_protocol::PATH, $member)
                .unwrap()
                .interface(sl_protocol::INTERFACE)
                .unwrap()
                .build($body)
                .unwrap()
        };
    }

    #[test]
    fn start_reboot_is_guarded_as_zero_argument() {
        assert!(ZERO_ARGUMENT_METHODS.contains(&"StartReboot"));
    }

    #[test]
    fn zero_argument_methods_accept_only_an_empty_body() {
        for member in ZERO_ARGUMENT_METHODS {
            assert!(!has_unexpected_arguments(
                member,
                &method_call!(member, &())
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &(0u32,))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("reboot",))
            ));
            assert!(has_unexpected_arguments(
                member,
                &method_call!(member, &("sl-reboot.service", "replace"))
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
