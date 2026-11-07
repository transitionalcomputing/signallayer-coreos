use super::*;
fn id(n: u128) -> Id { Id::parse(&format!("{n:032x}")).unwrap() }
fn object(n: u64) -> Object { Object { device: 1, inode: n, mount: 1 } }
fn observation() -> Observation {
    Observation { binding: Binding { boot: id(1), transaction: id(2), reset: id(3) },
        identity: Identity { uid: 201, gid: 201, subuid: Extent { start: 131072, count: 65536 },
            subgid: Extent { start: 196608, count: 65536 }, committed: true },
        content: Content { deployment: "1".repeat(64), build: W1_BUILD.into(), manifest: W1_MANIFEST.into(),
            artifact: F5_SHA256.into(), artifact_size: F5_SIZE, epoch: 1 },
        objects: Objects { rootfs: object(1), graph: object(2), runroot: object(3), data: object(4) },
        now: 100, lock_held: true, reset_live: true, permanent_spawn_closed: true,
        event_coverage_complete: true, unexpected_event: false, data_unchanged: true }
}
fn job() -> ExpectedJob { ExpectedJob {runtime:id(4),verifier:id(6),cgroup:object(7)} }
fn begin(o: &Observation) -> Coordinator {
    Coordinator::begin(o.binding.clone(), o.identity.clone(), o.content.clone(), o.objects.clone(), job(), o.now).unwrap()
}
fn persist(c: &mut Coordinator) {
    c.persist(Persistence { descriptor: c.descriptor().clone(), durable: true }).unwrap();
}
fn ready(o: &Observation) -> Coordinator { let mut c = begin(o); persist(&mut c); c.ready(o).unwrap(); c }
fn steps() -> Vec<Evidence> { vec![Evidence::SpawnClosed,
    Evidence::Teardown { processes: 0, holders: 0, ambiguous: false },
    Evidence::Isolated { graph_quarantined: true, runroot_cleared: true, ambiguous: false },
    Evidence::Configured { immutable_config: true, user_overrides: false, graph_empty: true, graph:object(2),runroot:object(3) },
    Evidence::ContentSelected { booted_deployment: true, read_only: true, exact_labels: true },
    Evidence::Preconditions { zero_survivors: true, zero_holders: true, maps_match: true,
        sandbox_valid: true, no_network: true, admission: true, storage_reserve: true }] }
fn preconditions(o: &Observation) -> Coordinator {
    let mut c=ready(o); for e in steps() { c.advance(o,e).unwrap(); persist(&mut c); } c
}
fn guard() -> GuardObservation {
    let own=Process { pid: 5, start_time: 99, cgroup: object(7) };
    GuardObservation { runtime: id(4), own, pidfd_matches: true, members: vec![own], populated_children: false }
}
fn runtime_observation() -> RuntimeObservation {
    RuntimeObservation { runtime: id(4), verifier: id(6), process: Process { pid: 8, start_time: 100, cgroup: object(7) },
        runtime_live: true, verifier_state: VerifierState::Succeeded, effective_content_matches: true, config_opens_match: true,
        containment_matches: true, health_ok: true }
}
fn running_observation() -> RuntimeObservation { let mut r=runtime_observation();r.verifier_state=VerifierState::Running;r }
fn launched(o:&Observation) -> Coordinator {
    let mut c=preconditions(o); c.guard(o,&guard(),id(6)).unwrap(); persist(&mut c); c.start_verifier(o,&running_observation()).unwrap();persist(&mut c);c
}
fn verified(o:&Observation) -> Coordinator {
    let mut c=launched(o); let r=runtime_observation(); let result=verify(c.descriptor(),o,&running_observation()).unwrap();
    c.accept_verification(o,result,&r).unwrap(); persist(&mut c); c
}
#[test] fn positive_full_lifecycle_requires_durable_publication() {
    let o=observation(); let r=runtime_observation(); let mut c=verified(&o);
    assert!(!c.trusted(&o,&r)); c.publish(&o,&r).unwrap(); assert!(!c.trusted(&o,&r));
    persist(&mut c); c.release_inhibit(&o,&r).unwrap(); let mut released=o.clone();released.lock_held=false; assert!(c.trusted(&released,&r)); assert_eq!(c.descriptor().sequence(),11);
}
#[test] fn malformed_and_zero_ids_refused() {
    for s in ["", "0", "00000000000000000000000000000000", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "gggggggggggggggggggggggggggggggg", "é000000000000000000000000000000"] { assert!(Id::parse(s).is_err()); }
    assert!(Id::parse("0123456789abcdef0123456789abcdef").is_ok());
}
#[test] fn identity_refusals() {
    let o=observation(); let mut variants=vec![];
    let mut i=o.identity.clone(); i.committed=false; variants.push(i);
    let mut i=o.identity.clone(); i.uid=0; variants.push(i);
    let mut i=o.identity.clone(); i.gid=0; variants.push(i);
    let mut i=o.identity.clone(); i.subuid.count=1; variants.push(i);
    let mut i=o.identity.clone(); i.subgid.start=u32::MAX; variants.push(i);
    let mut i=o.identity.clone(); i.uid=i.subuid.start; variants.push(i);
    for i in variants { assert!(Coordinator::begin(o.binding.clone(),i,o.content.clone(),o.objects.clone(),job(),o.now).is_err()); }
}
#[test] fn immutable_content_pins() {
    let o=observation();
    for n in 0..6 { let mut content=o.content.clone(); match n {
        0=>content.artifact="0".repeat(64), 1=>content.artifact_size+=1,
        2=>content.build="0".repeat(64), 3=>content.manifest="0".repeat(64),
        4=>content.epoch=2, _=>content.deployment="../other".into() }
        assert!(Coordinator::begin(o.binding.clone(),o.identity.clone(),content,o.objects.clone(),job(),o.now).is_err()); }
}
#[test] fn aliasing_or_missing_objects_refused() {
    let o=observation(); for n in 0..3 { let mut objects=o.objects.clone(); match n {
        0=>objects.graph=objects.data, 1=>objects.rootfs.inode=0, _=>objects.runroot.mount=0 }
        assert!(Coordinator::begin(o.binding.clone(),o.identity.clone(),o.content.clone(),objects,job(),o.now).is_err()); }
}
#[test] fn ready_after_state_one_persistence_before_spawn_inventory() {
    let mut o=observation(); o.permanent_spawn_closed=false; o.event_coverage_complete=false;
    let mut c=begin(&o); persist(&mut c); c.ready(&o).unwrap();
    assert_eq!(c.descriptor().state(),State::Inhibited);
    assert!(c.advance(&o,Evidence::SpawnClosed).is_err());
}
#[test] fn missing_durability_or_ready_refuses() {
    let o=observation(); let mut c=begin(&o); assert!(c.ready(&o).is_err());
    let mut c=begin(&o); persist(&mut c); assert!(c.advance(&o,Evidence::SpawnClosed).is_err());
}
#[test] fn stale_persistence_receipt_refuses() {
    let o=observation(); let mut c=ready(&o); let old=c.descriptor().clone();
    c.advance(&o,Evidence::SpawnClosed).unwrap();
    assert!(c.persist(Persistence { descriptor: old, durable:true }).is_err());
    assert_eq!(c.descriptor().state(),State::Failed);
}
#[test] fn failed_persistence_cannot_publish() {
    let o=observation(); let r=runtime_observation(); let mut c=verified(&o); c.publish(&o,&r).unwrap();
    assert!(c.persist(Persistence { descriptor:c.descriptor().clone(),durable:false }).is_err());
    assert!(!c.trusted(&o,&r));
}
#[test] fn phase_skip_refuses() {
    let o=observation(); for e in steps().into_iter().skip(1) {
        let mut c=ready(&o); assert!(c.advance(&o,e).is_err()); assert_eq!(c.descriptor().state(),State::Failed); }
}
#[test] fn negative_phase_evidence_refuses() {
    let o=observation(); let bad=vec![
        (1,Evidence::Teardown { processes:1,holders:0,ambiguous:false }),
        (1,Evidence::Teardown { processes:0,holders:1,ambiguous:false }),
        (1,Evidence::Teardown { processes:0,holders:0,ambiguous:true }),
        (2,Evidence::Isolated { graph_quarantined:false,runroot_cleared:true,ambiguous:false }),
        (2,Evidence::Isolated { graph_quarantined:true,runroot_cleared:true,ambiguous:true }),
        (3,Evidence::Configured { immutable_config:true,user_overrides:true,graph_empty:true,graph:object(2),runroot:object(3) }),
        (3,Evidence::Configured { immutable_config:true,user_overrides:false,graph_empty:false,graph:object(2),runroot:object(3) }),
        (4,Evidence::ContentSelected { booted_deployment:false,read_only:true,exact_labels:true }),
        (4,Evidence::ContentSelected { booted_deployment:true,read_only:false,exact_labels:true }),
        (4,Evidence::ContentSelected { booted_deployment:true,read_only:true,exact_labels:false })];
    for (count,e) in bad { let mut c=ready(&o); for good in steps().into_iter().take(count) { c.advance(&o,good).unwrap();persist(&mut c); }
        assert!(c.advance(&o,e).is_err()); }
}
#[test] fn every_precondition_required() {
    let o=observation(); for n in 0..7 { let mut c=ready(&o); for e in steps().into_iter().take(5) { c.advance(&o,e).unwrap();persist(&mut c); }
        assert!(c.advance(&o,Evidence::Preconditions { zero_survivors:n!=0,zero_holders:n!=1,maps_match:n!=2,
            sandbox_valid:n!=3,no_network:n!=4,admission:n!=5,storage_reserve:n!=6 }).is_err()); }
}
#[test] fn common_freshness_and_authority_refusals() {
    let o=observation(); for n in 0..13 { let mut bad=o.clone(); match n {
        0=>bad.binding.boot=id(99),1=>bad.binding.transaction=id(99),2=>bad.binding.reset=id(99),
        3=>bad.identity.uid+=1,4=>bad.content.manifest="0".repeat(64),5=>bad.objects.rootfs.mount+=1,
        6=>bad.lock_held=false,7=>bad.reset_live=false,8=>bad.permanent_spawn_closed=false,
        9=>bad.event_coverage_complete=false,10=>bad.unexpected_event=true,11=>bad.data_unchanged=false,
        _=>bad.now=99 }
        let mut c=preconditions(&o); assert!(c.guard(&bad,&guard(),id(6)).is_err()); }
}
#[test] fn monotonic_clock_cannot_go_backwards() {
    let mut o=observation(); let mut c=ready(&o); o.now+=2;c.advance(&o,Evidence::SpawnClosed).unwrap();persist(&mut c);
    o.now-=1; assert!(c.advance(&o,steps()[1].clone()).is_err());
}
#[test] fn guard_only_own_pidfd_confirmed_process() {
    let o=observation(); for n in 0..6 { let mut g=guard(); match n {
        0=>g.pidfd_matches=false,1=>g.members.clear(),2=>g.members.push(g.own),
        3=>g.populated_children=true,4=>g.members[0].start_time+=1,_=>g.own.pid=0 }
        let mut c=preconditions(&o); assert!(c.guard(&o,&g,id(6)).is_err()); }
}
#[test] fn guard_replay_is_terminal_and_failure_never_restores_token() {
    let o=observation(); let mut c=launched(&o); assert!(c.guard(&o,&guard(),id(6)).is_err());
    assert_eq!(c.descriptor().state(),State::Failed);
    assert!(c.guard(&o,&guard(),id(6)).is_err());
}
#[test] fn guard_requires_state_seven() {
    let o=observation(); let mut c=ready(&o); assert!(c.guard(&o,&guard(),id(6)).is_err());
}
#[test] fn verifier_cannot_run_before_guard() {
    let o=observation(); let c=preconditions(&o); assert!(verify(c.descriptor(),&o,&runtime_observation()).is_err());
}
#[test] fn verifier_requires_current_runtime_and_measured_content() {
    let o=observation(); let c=launched(&o); for n in 0..11 { let mut r=running_observation(); match n {
        0=>r.runtime=id(99),1=>r.verifier=id(99),2=>r.runtime_live=false,3=>r.verifier_state=VerifierState::Failed,
        4=>r.effective_content_matches=false,5=>r.config_opens_match=false,6=>r.containment_matches=false,
        7=>r.health_ok=false,8=>r.process.pid=0,9=>r.process.start_time=0,_=>r.process.cgroup=object(99) }
        assert!(verify(c.descriptor(),&o,&r).is_err()); }
}
#[test] fn delayed_verifier_result_after_restart_refuses() {
    let o=observation();let c=launched(&o);let r=runtime_observation();let result=verify(c.descriptor(),&o,&running_observation()).unwrap();
    let mut fresh=o.clone();fresh.binding.transaction=id(20);fresh.binding.reset=id(30);
    let mut restarted=launched(&fresh);assert!(restarted.accept_verification(&fresh,result,&r).is_err());
}
#[test] fn process_reuse_after_verification_refuses() {
    let o=observation();let mut c=launched(&o);let mut r=runtime_observation();let result=verify(c.descriptor(),&o,&running_observation()).unwrap();
    r.process.start_time+=1;assert!(c.accept_verification(&o,result,&r).is_err());
}
#[test] fn publication_rechecks_runtime_liveness_and_invocations() {
    let o=observation(); for n in 0..5 { let mut c=verified(&o);let mut r=runtime_observation();match n {
        0=>r.runtime_live=false,1=>r.runtime=id(99),2=>r.verifier=id(99),3=>r.process.pid+=1,_=>r.process.cgroup=object(99) }
        assert!(c.publish(&o,&r).is_err());assert!(!c.trusted(&o,&r)); }
}
#[test] fn event_gap_or_coordinator_loss_prevents_publication() {
    let o=observation();for n in 0..4 {let mut c=verified(&o);let mut bad=o.clone();match n {
        0=>bad.event_coverage_complete=false,1=>bad.reset_live=false,2=>bad.unexpected_event=true,_=>bad.lock_held=false }
        assert!(c.publish(&bad,&runtime_observation()).is_err());}
}
#[test] fn operational_query_requires_fresh_exclusion() {
    let o=observation();let r=runtime_observation();let mut c=verified(&o);c.publish(&o,&r).unwrap();persist(&mut c);
    c.release_inhibit(&o,&r).unwrap();let mut bad=o.clone();bad.lock_held=false;bad.permanent_spawn_closed=false;assert!(!c.trusted(&bad,&r));
    let mut dead=r.clone();dead.runtime_live=false;assert!(!c.trusted(&o,&dead));
}
#[test] fn restart_at_every_boundary_begins_state_one() {
    let o=observation();for count in 0..7 {let mut c=ready(&o);for e in steps().into_iter().take(count) {c.advance(&o,e).unwrap();persist(&mut c);}
        let fresh=Binding {boot:id(10),transaction:id(20),reset:id(30)};let next=c.restart(fresh,job(),false,200).unwrap();
        assert_eq!(next.descriptor().state(),State::Inhibited);assert_eq!(next.descriptor().sequence(),1);assert!(!next.durable);assert!(!next.guard_used);assert!(next.result.is_none());}
    for mut c in [launched(&o),verified(&o)] {c.fail();let next=c.restart(Binding {boot:id(10),transaction:id(20),reset:id(30)},job(),false,200).unwrap();assert_eq!(next.descriptor().state(),State::Inhibited);}
}
#[test] fn restart_rejects_reused_transaction_or_reset() {
    let o=observation();let c=ready(&o);let mut b=o.binding.clone();b.reset=id(20);assert!(c.restart(b,job(),false,200).is_err());
    let mut b=o.binding.clone();b.transaction=id(20);assert!(c.restart(b,job(),false,200).is_err());
}
#[test] fn failed_state_has_only_preserving_stop_plan() {
    let o=observation();let mut c=verified(&o);let p=c.fail();assert_eq!(p,FailurePlan {stop_runtime:true,stop_verifier:true,preserve_application_data:true,preserve_ambiguous_evidence:true});
    assert!(c.publish(&o,&runtime_observation()).is_err());assert!(!c.trusted(&o,&runtime_observation()));
}
#[test] fn sequence_overflow_fails_closed() {
    let o=observation();let mut c=ready(&o);c.descriptor.sequence=u64::MAX;
    assert!(c.advance(&o,Evidence::SpawnClosed).is_err());assert_eq!(c.descriptor().state(),State::Failed);
}
#[test] fn independent_expected_job_rejects_guard_selected_ids() {
    let o=observation();for n in 0..3 {let mut c=preconditions(&o);let mut g=guard();let mut v=id(6);
        match n {0=>g.runtime=id(44),1=>v=id(66),_=>{g.own.cgroup=object(99);g.members=vec![g.own];}}
        assert!(c.guard(&o,&g,v).is_err());}
}
#[test] fn verifier_deadline_does_not_bound_teardown() {
    let mut o=observation();let mut c=preconditions(&o);o.now=1000;
    c.guard(&o,&guard(),id(6)).unwrap();persist(&mut c);c.start_verifier(&o,&running_observation()).unwrap();persist(&mut c);let r=running_observation();
    let mut within=o.clone();within.now=1030;assert!(verify(c.descriptor(),&within,&r).is_ok());
    let mut late=o.clone();late.now=1031;assert!(verify(c.descriptor(),&late,&r).is_err());
    let result=verify(c.descriptor(),&o,&running_observation()).unwrap();assert!(c.accept_verification(&late,result,&runtime_observation()).is_err());
}
#[test] fn replacement_disposable_objects_update_descriptor_not_data() {
    let mut o=observation();let mut c=ready(&o);
    for e in steps().into_iter().take(3) {c.advance(&o,e).unwrap();persist(&mut c);}
    let old=c.descriptor().clone();
    c.advance(&o,Evidence::Configured {immutable_config:true,user_overrides:false,graph_empty:true,graph:object(22),runroot:object(33)}).unwrap();
    assert_eq!(c.descriptor().objects.data,old.objects.data);persist(&mut c);
    o.objects.graph=object(22);o.objects.runroot=object(33);
    c.advance(&o,steps()[4].clone()).unwrap();
}
#[test] fn replacement_cannot_alias_application_data() {
    let o=observation();let mut c=ready(&o);for e in steps().into_iter().take(3) {c.advance(&o,e).unwrap();persist(&mut c);}
    assert!(c.advance(&o,Evidence::Configured {immutable_config:true,user_overrides:false,graph_empty:true,graph:o.objects.data,runroot:object(33)}).is_err());
}
#[test] fn inhibit_cannot_release_before_durable_state_ten() {
    let o=observation();let r=runtime_observation();let mut c=verified(&o);
    assert!(c.release_inhibit(&o,&r).is_err());
    let mut c=verified(&o);c.publish(&o,&r).unwrap();assert!(c.release_inhibit(&o,&r).is_err());
}
#[test] fn operational_release_allows_long_lived_fresh_observations() {
    let o=observation();let r=runtime_observation();let mut c=verified(&o);c.publish(&o,&r).unwrap();persist(&mut c);
    c.release_inhibit(&o,&r).unwrap();let mut later=o.clone();later.lock_held=false;later.now=10000;
    assert!(c.trusted(&later,&r));later.permanent_spawn_closed=false;assert!(!c.trusted(&later,&r));
    let next=c.restart(Binding {boot:id(10),transaction:id(20),reset:id(30)},job(),false,20000).unwrap();
    assert_eq!(next.descriptor().state(),State::Inhibited);assert!(!next.ready);assert!(next.inhibited);
}
#[test] fn restart_backoff_and_exhaustion_are_bounded() {
    let mut b=RestartBudget::default();
    for now in [0,5,10,15] {assert_eq!(b.failed(now).unwrap(),Retry::WaitUntil(now+5));}
    assert_eq!(b.failed(20).unwrap(),Retry::Exhausted);
    assert_eq!(b.failed(21).unwrap(),Retry::Exhausted);
    assert!(b.failed(19).is_err());
    assert_eq!(b.failed(321).unwrap(),Retry::WaitUntil(326));
    assert!(b.failed(u64::MAX).is_err());
}
#[test] fn old_object_observation_after_recreation_is_stale() {
    let o=observation();let mut c=ready(&o);for e in steps().into_iter().take(3) {c.advance(&o,e).unwrap();persist(&mut c);}
    c.advance(&o,Evidence::Configured {immutable_config:true,user_overrides:false,graph_empty:true,graph:object(22),runroot:object(33)}).unwrap();persist(&mut c);
    assert!(c.advance(&o,steps()[4].clone()).is_err());
}
#[test] fn adverse_operational_observation_latches_failure() {
    let o=observation();let r=runtime_observation();for n in 0..3 {
        let mut c=verified(&o);c.publish(&o,&r).unwrap();persist(&mut c);c.release_inhibit(&o,&r).unwrap();
        let mut current=o.clone();current.lock_held=false;assert!(c.trusted(&current,&r));
        let mut bad=current.clone();let mut dead=r.clone();match n {0=>bad.reset_live=false,1=>bad.event_coverage_complete=false,_=>dead.runtime_live=false}
        assert!(!c.trusted(&bad,&dead));assert_eq!(c.descriptor().state(),State::Failed);
        assert!(!c.trusted(&current,&r));
    }
}
#[test] fn verifier_oneshot_success_is_not_permanent_liveness() {
    let o=observation();let mut c=launched(&o);let result=verify(c.descriptor(),&o,&running_observation()).unwrap();
    c.accept_verification(&o,result,&runtime_observation()).unwrap();persist(&mut c);
    c.publish(&o,&runtime_observation()).unwrap();persist(&mut c);c.release_inhibit(&o,&runtime_observation()).unwrap();
    let mut current=o.clone();current.lock_held=false;assert!(c.trusted(&current,&runtime_observation()));
}
#[test] fn verifier_start_is_one_use_and_clock_starts_at_activation() {
    let mut o=observation();let mut c=preconditions(&o);c.guard(&o,&guard(),id(6)).unwrap();persist(&mut c);
    o.now=1000;c.start_verifier(&o,&running_observation()).unwrap();persist(&mut c);
    o.now=1030;assert!(verify(c.descriptor(),&o,&running_observation()).is_ok());
    assert!(c.start_verifier(&o,&running_observation()).is_err());
}
#[test] fn verifier_process_must_match_activation_snapshot() {
    let o=observation();let c=launched(&o);let mut r=running_observation();r.process.start_time+=1;
    assert!(verify(c.descriptor(),&o,&r).is_err());
}
#[test] fn fixture_retry_in_same_live_reset_uses_new_transaction() {
    let o=observation();let mut c=launched(&o);c.fail();let mut binding=o.binding.clone();binding.transaction=id(55);
    let next=c.retry_in_live_reset(binding,job(),&o).unwrap();
    assert_eq!(next.descriptor().state(),State::Inhibited);assert_eq!(next.descriptor().binding().reset,o.binding.reset);
    assert!(!next.guard_used);assert!(next.result.is_none());assert!(!next.durable);
}
#[test] fn live_retry_rejects_stale_or_dead_coordinator() {
    let o=observation();for n in 0..5 {let mut c=launched(&o);c.fail();let mut binding=o.binding.clone();binding.transaction=id(55);let mut current=o.clone();
        match n {0=>binding.transaction=o.binding.transaction,1=>current.reset_live=false,2=>binding.reset=id(66),3=>current.binding.transaction=id(66),_=>binding.boot=id(66)}
        assert!(c.retry_in_live_reset(binding,job(),&current).is_err());}
}
#[test] fn coordinator_restart_rejects_still_live_previous_instance() {
    let o=observation();let c=launched(&o);let binding=Binding {boot:id(10),transaction:id(20),reset:id(30)};
    assert!(c.restart(binding,job(),true,200).is_err());
}
#[test] fn operational_application_data_writes_are_allowed() {
    let o=observation();let r=runtime_observation();let mut c=verified(&o);c.publish(&o,&r).unwrap();persist(&mut c);c.release_inhibit(&o,&r).unwrap();
    let mut live=o.clone();live.lock_held=false;live.data_unchanged=false;assert!(c.trusted(&live,&r));
    live.objects.data=object(99);assert!(!c.trusted(&live,&r));
}
