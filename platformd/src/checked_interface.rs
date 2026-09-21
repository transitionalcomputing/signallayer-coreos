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
// or starts bootc. All normal dispatch and introspection remain generated.
pub(super) struct CheckedPlatform(pub(super) Platform);

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
        if name.as_str() == "GetStatus"
            && (msg.body().signature() != &zbus::zvariant::Signature::Unit
                || !msg.body().is_empty())
        {
            return DispatchResult2::new_async(connection, msg, async {
                Err::<String, _>(fdo::Error::InvalidArgs(
                    "GetStatus takes no arguments".into(),
                ))
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
