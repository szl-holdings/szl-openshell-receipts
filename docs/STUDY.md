# Study dossier: NVIDIA OpenShell and NVIDIA AI security research

Method: SZL fashion methodology. Study the construction of leading work, never copy it, then recombine through SZL software, math and doctrine.

## Archive (what was studied)
- NVIDIA OpenShell README and Policy Advisor docs: default-deny sandboxes, agent-authored policy proposals, a prover with four categorical findings (link_local_reach, l7_bypass_credentialed, credential_reach_expansion, capability_expansion), review tokens bound to live inputs, CONFIG:* audit events. https://github.com/NVIDIA/openshell and https://docs.nvidia.com/openshell/sandboxes/policy-advisor
- NVIDIA "Security in the Age of AI" research hub: transparent insights, reproducible results, practical security; security as engineering with requirements, controls, named owners and evidence; the combinatorial blind spot of multimodal inputs; the harness around the model matters. https://research.nvidia.com/ai-security

## Not copied
No OpenShell source, prover implementation or text is reused. Categories are referenced by name for interoperability.

## Silhouette
OpenShell decides what an agent may do. SZL proves what happened, independently re-derives what a policy change would grant, and binds every human decision.

## Material (SZL originals)
- Reach-set witness: policies as sets of (binary, host, port, method, credentialed); delta = new minus old; expansion_ratio = |added| / max(1, |old|).
- Two-witness gate: ALLOW_ELIGIBLE only when both witnesses report nothing; disagreement forces review.
- Anomaly flag: auto-approval with a non-empty prover delta.
- Controls ledger with MEASURED / REPORTED / UNKNOWN / UNAVAILABLE labels.
- Combined multimodal digest.

## Runway (next)
Capture real events from one read-only sandbox, pin the field mapping (C-05), wire DSSE (C-07), publish a verifiable timeline on a11oy.net.
