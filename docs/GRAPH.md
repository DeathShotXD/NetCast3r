# The evidence graph and attack paths

Penligent calls this attack-path management. NetCast3r's version keeps one
rule the public material does not describe: every node and every edge is
either derived from a real observation or added explicitly by an agent, and
every edge records that provenance and a confidence. The graph never presents
a guess as a fact.

## Nodes and edges

`src/netcast3r/graph.py` builds the graph from stored evidence only:

- the mission **target** and its **scope** entries;
- **endpoints** found in agent notes, hypotheses, findings, and tool calls;
- **hypotheses**, marked `confidence: hypothesis`, because a falsifiable lead
  is a claim, not an observation;
- **findings**, with the severity the finding actually carries.

Edge kinds: `resolves_to`, `in_scope`, `exposes`, `tests`, `tested_by`,
`leads_to`, `verified_by`. Every edge carries an `evidence` object naming the
tool call, run, note, hypothesis, or finding it came from. Rebuilding is
idempotent: nodes are unique by `(mission, kind, key)` and edges by
`(mission, src, dst, kind)`.

Agents can add a node or edge they actually observed with `graph_node_add` and
`graph_edge_add` (mask any secret value, and use `confidence: hypothesis` for
a claim that is not yet observed).

## Candidate paths

`derive_paths` proposes chains toward an impact:

- one path per open hypothesis, whose first step is the hypothesis test and
  whose second step, when a finding exists on the same host, is an impact
  confirmation;
- one surface-review path per host that has endpoints but no open lead.

Each path is stored with its steps and a verification state: `candidate`,
`verifying`, `verified`, `partial`, `refuted`, `blocked`, or `inconclusive`.

## Verification

`path_verify` runs a path's steps in order through the same scoped,
risk-gated tools every other caller uses. A verifier may only run a read or
probe: `http_probe`, `http_request`, `http_path_diff`, `http_upload`,
`oracle_extract`, the race tools, and `host_probe`. Anything else is `blocked`.

Each step's observation is judged by the configured model against the step's
expected observation: `supports`, `refutes`, or `inconclusive`. With no model
reachable, every step is honestly `inconclusive`. The path state aggregates
the steps: all supported is `verified`, a supported step contradicted is
`partial`, all refuted is `refuted`, all refused is `blocked`.

A path verifier creates no finding and spends no approval. A promoted finding
is still a separate, human-gated write.

## Surface

HTTP:

| method | path | purpose |
| --- | --- | --- |
| `POST` | `/api/v1/missions/{id}/graph/build` | rebuild the graph and derive paths |
| `GET` | `/api/v1/missions/{id}/graph` | nodes, edges, and paths |
| `GET` | `/api/v1/missions/{id}/paths` | candidate paths |
| `POST` | `/api/v1/paths/{id}/verify` | start a path verification as a live run |
| `POST` | `/api/v1/paths/{id}/stop` | cancel a path verification |
| `POST` | `/api/v1/missions/{id}/graph/nodes` | add or update a node |
| `POST` | `/api/v1/missions/{id}/graph/edges` | add or update an edge |

MCP exposes `graph_build`, `mission_graph`, `paths_list`, `path_verify`,
`graph_node_add`, and `graph_edge_add`.

The mission detail in the dashboard has a **Graph** tab: a deterministic
layered SVG of the nodes and edges, the counts, and the candidate paths with a
**Verify** action that starts a live run.

## State

Tables `graph_nodes`, `graph_edges`, and `graph_paths` in the index. A rebuild
never deletes an agent-added node or edge; it only upserts what the evidence
supports.
