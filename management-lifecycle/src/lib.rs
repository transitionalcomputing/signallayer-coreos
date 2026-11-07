//! P3-1d pure lifecycle core. No filesystem, process, service or network backend.
//! Observations and persistence receipts are trusted-adapter inputs, not proof
//! of kernel state. This library cannot authorize a production launch alone.
#![forbid(unsafe_code)]

pub const F5_SHA256: &str = "deeae34d74b6933d7b3ee88b7780a340a19267cc7eac0bee1320226adee93093";
pub const F5_SIZE: u64 = 15_725_600;
pub const W1_BUILD: &str = "b337d0a5f8e7c13bd584735488a9afa9caa1855c8478f1cdf9a0240888852872";
pub const W1_MANIFEST: &str = "aab21ed687cede0d67093f4fb28b595a983562ea76d833b6b2bea529d036af5a";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { InvalidIdentity, InvalidContent, InvalidObject, Stale, WrongState,
    NotDurable, NotReady, UnsafeObservation, Replay, Timeout, Overflow, Failed }
pub type Result<T> = std::result::Result<T, Error>;

/// Nonzero systemd/boot/transaction identity. Parsing accepts exact lowercase
/// 128-bit hex only; wire-format conversion belongs to a later fixed adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Id([u8; 16]);
impl Id {
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() != 32 || !s.bytes().all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x)) {
            return Err(Error::InvalidIdentity);
        }
        let mut bytes = [0; 16];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2*i..2*i+2], 16).map_err(|_| Error::InvalidIdentity)?;
        }
        if bytes == [0; 16] { return Err(Error::InvalidIdentity); }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding { pub boot: Id, pub transaction: Id, pub reset: Id }
/// Independently selected by the coordinator adapter, never taken from guard/result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedJob { pub runtime: Id, pub verifier: Id, pub cgroup: Object }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extent { pub start: u32, pub count: u32 }
impl Extent {
    fn valid(self, primary: u32) -> bool {
        self.count == 65_536 && self.start >= 100_000
            && self.start % 65_536 == 0
            && self.start.checked_add(self.count).is_some()
            && !(self.start..self.start + self.count).contains(&primary)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity { pub uid: u32, pub gid: u32, pub subuid: Extent, pub subgid: Extent,
    pub committed: bool }
impl Identity {
    fn validate(&self) -> Result<()> {
        if !self.committed || self.uid == 0 || self.gid == 0
            || !self.subuid.valid(self.uid) || !self.subgid.valid(self.gid) {
            return Err(Error::InvalidIdentity);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Content { pub deployment: String, pub build: String, pub manifest: String,
    pub artifact: String, pub artifact_size: u64, pub epoch: u32 }
impl Content {
    fn validate(&self) -> Result<()> {
        if self.deployment.len() != 64 || !self.deployment.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.deployment.bytes().all(|b| b == b'0')
            || self.build != W1_BUILD || self.manifest != W1_MANIFEST
            || self.artifact != F5_SHA256 || self.artifact_size != F5_SIZE || self.epoch != 1 {
            return Err(Error::InvalidContent);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object { pub device: u64, pub inode: u64, pub mount: u64 }
impl Object { fn valid(self) -> bool { self.inode != 0 && self.mount != 0 } }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Objects { pub rootfs: Object, pub graph: Object, pub runroot: Object, pub data: Object }
impl Objects {
    fn validate(&self) -> Result<()> {
        let all = [self.rootfs, self.graph, self.runroot, self.data];
        for (i, a) in all.iter().enumerate() {
            if !a.valid() || all[..i].iter().any(|b| a.device == b.device && a.inode == b.inode) {
                return Err(Error::InvalidObject);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State { Inhibited = 1, SpawnClosed, TeardownVerified, Isolated, Configured,
    ContentSelected, Preconditions, Launched, Verified, Operational, Failed }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Descriptor {
    binding: Binding, identity: Identity, content: Content, objects: Objects,
    state: State, sequence: u64, started: u64, expected_job: ExpectedJob, verifier_started: Option<u64>, runtime: Option<Id>, verifier: Option<Id>, runtime_cgroup: Option<Object>, runtime_process: Option<Process>,
}
impl Descriptor {
    pub fn state(&self) -> State { self.state }
    pub fn sequence(&self) -> u64 { self.sequence }
    pub fn binding(&self) -> &Binding { &self.binding }
    pub fn content(&self) -> &Content { &self.content }
}
/// Later adapter must obtain this only after create/write/fsync/rename/dir-fsync
/// of the exact descriptor under validated root-owned authority. Pure tests fake it.
#[derive(Clone, Debug)]
pub struct Persistence { pub descriptor: Descriptor, pub durable: bool }

/// Fresh common observation, required at every transition and publication.
/// No elapsed-time sampling or a true boolean alone proves real exclusion.
#[derive(Clone, Debug)]
pub struct Observation {
    pub binding: Binding, pub identity: Identity, pub content: Content, pub objects: Objects,
    pub now: u64, pub lock_held: bool, pub reset_live: bool,
    pub permanent_spawn_closed: bool, pub event_coverage_complete: bool,
    pub unexpected_event: bool, pub data_unchanged: bool,
}
#[derive(Clone, Debug)]
pub enum Evidence {
    SpawnClosed,
    Teardown { processes: usize, holders: usize, ambiguous: bool },
    Isolated { graph_quarantined: bool, runroot_cleared: bool, ambiguous: bool },
    Configured { immutable_config: bool, user_overrides: bool, graph_empty: bool, graph: Object, runroot: Object },
    ContentSelected { booted_deployment: bool, read_only: bool, exact_labels: bool },
    Preconditions { zero_survivors: bool, zero_holders: bool, maps_match: bool,
        sandbox_valid: bool, no_network: bool, admission: bool, storage_reserve: bool },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Process { pub pid: u32, pub start_time: u64, pub cgroup: Object }
#[derive(Clone, Debug)]
pub struct GuardObservation {
    pub runtime: Id, pub own: Process, pub pidfd_matches: bool,
    pub members: Vec<Process>, pub populated_children: bool,
}
#[derive(Clone, Debug)]
pub enum VerifierState { Running, Succeeded, Failed }
#[derive(Clone, Debug)]
pub struct RuntimeObservation {
    pub runtime: Id, pub verifier: Id, pub process: Process,
    pub runtime_live: bool, pub verifier_state: VerifierState,
    pub effective_content_matches: bool, pub config_opens_match: bool,
    pub containment_matches: bool, pub health_ok: bool,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedResult { descriptor: Descriptor, process: Process, checked_at: u64 }

/// Pure independent verifier: produces a result but has no coordinator access,
/// persistence interface, repair operation or trusted-state publication method.
pub fn verify(d: &Descriptor, o: &Observation, r: &RuntimeObservation) -> Result<VerifiedResult> {
    common(d, o)?;
    if d.state != State::Launched || d.runtime != Some(r.runtime)
        || d.verifier != Some(r.verifier) || d.runtime_cgroup != Some(r.process.cgroup) || d.runtime_process != Some(r.process) { return Err(Error::Stale); }
    runtime(r)?;
    if !matches!(r.verifier_state, VerifierState::Running) { return Err(Error::UnsafeObservation); }
    let started = d.verifier_started.ok_or(Error::Stale)?;
    if o.now < started || o.now - started > 30 { return Err(Error::Timeout); }
    Ok(VerifiedResult { descriptor: d.clone(), process: r.process, checked_at: o.now })
}
fn runtime(r: &RuntimeObservation) -> Result<()> {
    if !r.runtime_live || r.process.pid == 0 || r.process.start_time == 0
        || !r.process.cgroup.valid() || !r.effective_content_matches || !r.config_opens_match
        || !r.containment_matches || !r.health_ok { return Err(Error::UnsafeObservation); }
    Ok(())
}
fn common(d: &Descriptor, o: &Observation) -> Result<()> {
    if d.binding != o.binding || d.identity != o.identity || d.content != o.content
        || d.objects != o.objects { return Err(Error::Stale); }
    if o.now < d.started { return Err(Error::Timeout); }
    if (d.state != State::Operational && !o.lock_held) || !o.reset_live || o.unexpected_event || (d.state != State::Operational && !o.data_unchanged)
        || (d.state != State::Inhibited && (!o.permanent_spawn_closed || !o.event_coverage_complete)) {
        return Err(Error::UnsafeObservation);
    }
    Ok(())
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FailurePlan {
    pub stop_runtime: bool, pub stop_verifier: bool,
    pub preserve_application_data: bool, pub preserve_ambiguous_evidence: bool,
}
/// No Clone: one coordinator owns a one-use guard token in this process.
/// Cross-process serialization, durable replay protection and effect execution
/// remain adapter/integration requirements, not properties of this model.
pub struct Coordinator { descriptor: Descriptor, durable: bool, ready: bool,
    guard_used: bool, result: Option<VerifiedResult>, last_observed: u64, inhibited: bool }
impl Coordinator {
    pub fn begin(binding: Binding, identity: Identity, content: Content, objects: Objects, expected_job: ExpectedJob, now: u64) -> Result<Self> {
        identity.validate()?; content.validate()?; objects.validate()?;
        if !expected_job.cgroup.valid() || expected_job.runtime == expected_job.verifier { return Err(Error::InvalidIdentity); }
        Ok(Self { descriptor: Descriptor { binding, identity, content, objects,
            state: State::Inhibited, sequence: 1, started: now, expected_job, verifier_started: None, runtime: None, verifier: None, runtime_cgroup: None, runtime_process: None },
            durable: false, ready: false, guard_used: false, result: None, last_observed: now, inhibited: true })
    }
    pub fn descriptor(&self) -> &Descriptor { &self.descriptor }
    pub fn persist(&mut self, receipt: Persistence) -> Result<()> {
        if !receipt.durable || receipt.descriptor != self.descriptor { return self.reject(Error::NotDurable); }
        if self.descriptor.state == State::Failed { return Err(Error::Failed); }
        self.durable = true; Ok(())
    }
    /// READY after durable state-1 lock, before any launch request. This does
    /// not call sd_notify or prove multi-user.target ordering.
    pub fn ready(&mut self, observation: &Observation) -> Result<()> {
        let checked = common(&self.descriptor, observation);
        if let Err(e) = checked { return self.reject(e); }
        if self.descriptor.state != State::Inhibited { return self.reject(Error::WrongState); }
        if !self.durable { return self.reject(Error::NotDurable); }
        self.ready = true; Ok(())
    }
    fn reject<T>(&mut self, error: Error) -> Result<T> {
        self.descriptor.state = State::Failed; self.durable = false;
        self.guard_used = true; self.result = None; Err(error)
    }
    fn check(&mut self, o: &Observation) -> Result<()> {
        if self.descriptor.state == State::Failed { return Err(Error::Failed); }
        if !self.durable { return self.reject(Error::NotDurable); }
        if let Err(e) = common(&self.descriptor, o) { return self.reject(e); }
        if o.now < self.last_observed { return self.reject(Error::Stale); }
        self.last_observed = o.now;
        if !self.ready { return self.reject(Error::NotReady); }
        Ok(())
    }
    fn transition(&mut self, next: State) -> Result<()> {
        let sequence = match self.descriptor.sequence.checked_add(1) {
            Some(x) => x, None => return self.reject(Error::Overflow),
        };
        self.descriptor.sequence = sequence; self.descriptor.state = next; self.durable = false; Ok(())
    }
    pub fn advance(&mut self, observation: &Observation, evidence: Evidence) -> Result<()> {
        self.check(observation)?;
        let next = match (self.descriptor.state, evidence) {
            (State::Inhibited, Evidence::SpawnClosed) if observation.permanent_spawn_closed && observation.event_coverage_complete => State::SpawnClosed,
            (State::SpawnClosed, Evidence::Teardown { processes: 0, holders: 0, ambiguous: false }) => State::TeardownVerified,
            (State::TeardownVerified, Evidence::Isolated { graph_quarantined: true, runroot_cleared: true, ambiguous: false }) => State::Isolated,
            (State::Isolated, Evidence::Configured { immutable_config: true, user_overrides: false, graph_empty: true, graph, runroot }) => {
                let mut replacement = self.descriptor.objects.clone(); replacement.graph=graph; replacement.runroot=runroot;
                if let Err(e) = replacement.validate() { return self.reject(e); }
                self.descriptor.objects = replacement; State::Configured
            },
            (State::Configured, Evidence::ContentSelected { booted_deployment: true, read_only: true, exact_labels: true }) => State::ContentSelected,
            (State::ContentSelected, Evidence::Preconditions { zero_survivors: true, zero_holders: true,
                maps_match: true, sandbox_valid: true, no_network: true, admission: true, storage_reserve: true }) => State::Preconditions,
            _ => return self.reject(Error::UnsafeObservation),
        };
        self.transition(next)
    }
    /// One-use source-level guard; consumes authorization even on refusal.
    /// Adapter must enforce exact fixed service, pidfd and durable binding.
    pub fn guard(&mut self, observation: &Observation, g: &GuardObservation, verifier: Id) -> Result<()> {
        self.check(observation)?;
        if self.guard_used { return self.reject(Error::Replay); }
        self.guard_used = true;
        if self.descriptor.state != State::Preconditions || !g.pidfd_matches
            || g.runtime != self.descriptor.expected_job.runtime || verifier != self.descriptor.expected_job.verifier
            || g.own.cgroup != self.descriptor.expected_job.cgroup
            || g.own.pid == 0 || g.own.start_time == 0 || !g.own.cgroup.valid()
            || g.members != [g.own] || g.populated_children {
            return self.reject(Error::UnsafeObservation);
        }
        self.descriptor.runtime_cgroup = Some(g.own.cgroup);
        self.descriptor.runtime = Some(g.runtime);
        self.transition(State::Launched)
    }
    /// Model the actual verifier activation, after runtime launch. A start can
    /// bind once only; persisting this exact descriptor precedes measurement.
    pub fn start_verifier(&mut self, o: &Observation, r: &RuntimeObservation) -> Result<()> {
        self.check(o)?;
        if self.descriptor.state != State::Launched || self.descriptor.verifier_started.is_some()
            || self.descriptor.runtime != Some(r.runtime) || self.descriptor.expected_job.verifier != r.verifier
            || self.descriptor.runtime_cgroup != Some(r.process.cgroup) || !r.runtime_live
            || r.process.pid == 0 || r.process.start_time == 0
            || !matches!(r.verifier_state, VerifierState::Running) { return self.reject(Error::Stale); }
        self.descriptor.runtime_process=Some(r.process);
        self.descriptor.verifier=Some(r.verifier); self.descriptor.verifier_started=Some(o.now);
        self.transition(State::Launched)
    }
    pub fn accept_verification(&mut self, o: &Observation, result: VerifiedResult, r: &RuntimeObservation) -> Result<()> {
        self.check(o)?;
        if self.descriptor.state != State::Launched || result.descriptor != self.descriptor
            || result.checked_at > o.now || result.process != r.process {
            return self.reject(Error::Stale);
        }
        if self.descriptor.runtime != Some(r.runtime) || self.descriptor.verifier != Some(r.verifier)
            || self.descriptor.runtime_cgroup != Some(r.process.cgroup)
            || !matches!(r.verifier_state, VerifierState::Succeeded) { return self.reject(Error::Stale); }
        if let Err(e) = runtime(r) { return self.reject(e); }
        if self.descriptor.verifier_started.map(|t| o.now < t || o.now-t > 30).unwrap_or(true) { return self.reject(Error::Timeout); }
        self.result = Some(result); self.transition(State::Verified)
    }
    pub fn publish(&mut self, o: &Observation, r: &RuntimeObservation) -> Result<()> {
        self.check(o)?;
        if self.descriptor.state != State::Verified { return self.reject(Error::WrongState); }
        let result = match &self.result { Some(x) => x, None => return self.reject(Error::Stale) };
        if self.descriptor.runtime != Some(r.runtime) || self.descriptor.verifier != Some(r.verifier)
            || self.descriptor.runtime_cgroup != Some(r.process.cgroup)
            || result.process != r.process || result.checked_at > o.now {
            return self.reject(Error::Stale);
        }
        if !matches!(r.verifier_state, VerifierState::Succeeded) { return self.reject(Error::Stale); }
        if let Err(e) = runtime(r) { return self.reject(e); }
        if o.now < result.checked_at || self.descriptor.verifier_started.map(|t| o.now < t || o.now-t > 30).unwrap_or(true) { return self.reject(Error::Timeout); }
        self.transition(State::Operational)
    }
    /// Release temporary inhibit only after durable state 10; permanent exclusion
    /// remains required. This returns a model decision, not an unlock syscall.
    pub fn release_inhibit(&mut self, o: &Observation, r: &RuntimeObservation) -> Result<()> {
        self.check(o)?;
        if self.descriptor.state != State::Operational || !self.inhibited || !o.lock_held
            || self.descriptor.runtime != Some(r.runtime) || self.descriptor.verifier != Some(r.verifier)
            || self.result.as_ref().map(|x| x.process != r.process).unwrap_or(true) {
            return self.reject(Error::WrongState);
        }
        if !matches!(r.verifier_state, VerifierState::Succeeded) { return self.reject(Error::Stale); }
        if let Err(e) = runtime(r) { return self.reject(e); }
        self.inhibited=false; Ok(())
    }
    /// Query requires fresh observations; never cache a true answer as authority.
    pub fn trusted(&mut self, o: &Observation, r: &RuntimeObservation) -> bool {
        if self.descriptor.state != State::Operational || !self.durable || self.inhibited { return false; }
        let accepted = !o.lock_held && o.now >= self.last_observed
            && common(&self.descriptor, o).is_ok() && runtime(r).is_ok()
            && matches!(r.verifier_state, VerifierState::Succeeded)
            && self.descriptor.runtime_cgroup == Some(r.process.cgroup)
            && self.descriptor.runtime == Some(r.runtime) && self.descriptor.verifier == Some(r.verifier)
            && self.result.as_ref().map(|x| x.process == r.process).unwrap_or(false);
        if accepted { self.last_observed=o.now; } else { self.fail(); }
        accepted
    }
    pub fn fail(&mut self) -> FailurePlan {
        let _: Result<()> = self.reject(Error::Failed);
        FailurePlan { stop_runtime: true, stop_verifier: true,
            preserve_application_data: true, preserve_ambiguous_evidence: true }
    }
    /// A failed fixture may retry in the same live coordinator invocation.
    /// The adapter supplies a newly acquired state-1 lock and current context;
    /// a new transaction is mandatory, and no previous token/result survives.
    pub fn retry_in_live_reset(&self, binding: Binding, expected_job: ExpectedJob, current: &Observation) -> Result<Self> {
        if self.descriptor.state != State::Failed || !current.reset_live || !current.lock_held
            || current.binding != self.descriptor.binding || current.now < self.last_observed
            || current.identity != self.descriptor.identity || current.content != self.descriptor.content
            || current.objects != self.descriptor.objects || binding.boot != current.binding.boot
            || binding.reset != current.binding.reset || binding.transaction == current.binding.transaction {
            return Err(Error::Stale);
        }
        Self::begin(binding, current.identity.clone(), current.content.clone(), current.objects.clone(), expected_job, current.now)
    }
    /// A real coordinator restart requires a different reset InvocationID and
    /// confirmation that the previous reset is no longer live. Never resume an
    /// intermediate state or retain a token/result. This is simulated evidence.
    pub fn restart(&self, binding: Binding, expected_job: ExpectedJob, previous_reset_live: bool, now: u64) -> Result<Self> {
        if previous_reset_live || binding.transaction == self.descriptor.binding.transaction
            || binding.reset == self.descriptor.binding.reset { return Err(Error::Replay); }
        Self::begin(binding, self.descriptor.identity.clone(), self.descriptor.content.clone(), self.descriptor.objects.clone(), expected_job, now)
    }
}

#[cfg(test)]
mod tests;

/// Pure model of the already proposed RestartSec=5s, burst=5/300s policy.
/// It schedules no timer and starts no service. A runtime failure must first
/// invalidate its coordinator; permission to retry is not permission to resume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry { WaitUntil(u64), Exhausted }
#[derive(Default)]
pub struct RestartBudget { failures: Vec<u64>, last: Option<u64> }
impl RestartBudget {
    pub fn failed(&mut self, now: u64) -> Result<Retry> {
        if self.last.map(|t| now < t).unwrap_or(false) { return Err(Error::Stale); }
        let next = now.checked_add(5).ok_or(Error::Overflow)?;
        self.last=Some(now);
        self.failures.retain(|t| now - *t < 300);
        self.failures.push(now);
        if self.failures.len() >= 5 { Ok(Retry::Exhausted) } else { Ok(Retry::WaitUntil(next)) }
    }
}
