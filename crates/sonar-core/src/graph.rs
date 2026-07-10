use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity::{Entity, EntityId};
use crate::probe::{ProbeCtx, ProbeDescriptor, ProbeOutput};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Verified,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Observed,
    ResolvesTo,
    HasPort,
    HasCertificate,
    ContainsDnsRecord,
    BelongsToAsn,
    RedirectsTo,
    DiscoveredBy,
    Related,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provenance {
    pub probe_id: String,
    pub run_id: Uuid,
    pub observed_at: DateTime<Utc>,
    pub confidence: Confidence,
}

impl Provenance {
    pub fn from_probe(
        descriptor: &ProbeDescriptor,
        ctx: &ProbeCtx,
        confidence: Confidence,
    ) -> Self {
        Self {
            probe_id: descriptor.id.clone(),
            run_id: ctx.run_id,
            observed_at: Utc::now(),
            confidence,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityNode {
    pub id: EntityId,
    pub entity: Entity,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub provenance: Vec<Provenance>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntityEdge {
    pub from: EntityId,
    pub to: EntityId,
    pub relation: RelationKind,
    pub provenance: Provenance,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PivotGraph {
    pub nodes: BTreeMap<EntityId, EntityNode>,
    pub edges: Vec<EntityEdge>,
}

impl PivotGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn upsert_entity(&mut self, entity: Entity, provenance: Provenance) -> EntityId {
        let now = Utc::now();
        let id = entity.id();

        self.nodes
            .entry(id.clone())
            .and_modify(|node| {
                node.last_seen = now;
                node.provenance.push(provenance.clone());
            })
            .or_insert_with(|| EntityNode {
                id: id.clone(),
                entity,
                first_seen: now,
                last_seen: now,
                provenance: vec![provenance],
            });

        id
    }

    pub fn add_edge(
        &mut self,
        from: EntityId,
        to: EntityId,
        relation: RelationKind,
        provenance: Provenance,
    ) {
        self.edges.push(EntityEdge {
            from,
            to,
            relation,
            provenance,
        });
    }

    pub fn apply_probe_output(
        &mut self,
        source: &Entity,
        descriptor: &ProbeDescriptor,
        ctx: &ProbeCtx,
        output: &ProbeOutput,
    ) {
        let source_provenance = Provenance::from_probe(descriptor, ctx, Confidence::Verified);
        let source_id = self.upsert_entity(source.clone(), source_provenance.clone());

        for discovered in &output.discovered {
            let provenance = Provenance::from_probe(descriptor, ctx, discovered.confidence);
            let target_id = self.upsert_entity(discovered.entity.clone(), provenance.clone());
            self.add_edge(
                source_id.clone(),
                target_id,
                discovered.relation.clone(),
                provenance,
            );
        }

        for draft in &output.edges {
            let provenance = Provenance::from_probe(descriptor, ctx, draft.confidence);
            let target_id = self.upsert_entity(draft.to.clone(), provenance.clone());
            self.add_edge(
                draft.from.clone().unwrap_or_else(|| source_id.clone()),
                target_id,
                draft.relation.clone(),
                provenance,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::entity::parse_entity_guess;
    use crate::probe::{ProbeCategory, ProbeCtx, ProbeDescriptor, ProbeRisk, ProbeStatus};
    use crate::scope::ScopeGuard;

    use super::*;

    #[test]
    fn dedupes_nodes_by_stable_entity_id() {
        let descriptor = ProbeDescriptor {
            id: "test.probe".into(),
            name: "Test Probe".into(),
            description: "test".into(),
            category: ProbeCategory::Core,
            status: ProbeStatus::Ready,
            risk: ProbeRisk::Passive,
            requirements: vec![],
        };
        let ctx = ProbeCtx::new(ScopeGuard::default());
        let entity = parse_entity_guess("Example.com").unwrap();
        let mut graph = PivotGraph::new();
        let provenance = Provenance::from_probe(&descriptor, &ctx, Confidence::Verified);

        graph.upsert_entity(entity.clone(), provenance.clone());
        graph.upsert_entity(entity, provenance);

        assert_eq!(graph.nodes.len(), 1);
    }
}
