# Detection Development Lifecycle (DDLC)

This flowchart defines the standard operating procedure for developing new detection rules in this repository.

```mermaid
%%{init: {"flowchart": {"htmlLabels": true, "curve": "linear", "padding": 15}}}%%
flowchart LR
    %% Phase 1: Input and Strategy
    subgraph P1 ["Phase 1: Input & Strategy<br/>(CTI / IR Analyst)"]
        direction TB
        A[CTI: Threat Intel &<br/>TTP Extraction] --> C{Requirement<br/>Assessment}
        B[IR: Incident Review<br/>& Post-Mortem] --> C
    end

    %% Phase 2: Logic Design
    subgraph P2 ["Phase 2: Detection Engineering<br/>(Detection Engineer)"]
        direction TB
        C --> D[Use Case Design:<br/>Logic Modeling & Sigma]
        D --> E[Data Requirements:<br/>Fields & Schema Mapping]
    end

    %% Phase 3: Engineering Implementation
    subgraph P3 ["Phase 3: Security Engineering<br/>(Security Engineer)"]
        direction TB
        E --> F[Gap Analysis:<br/>Visibility Gaps]
        F --> G[Ingestion & Pipeline:<br/>Parser & Normalization]
        G --> H[Data Quality Check:<br/>Schema & Latency]
    end

    %% Phase 4: Validation, Ops & Knowledge
    subgraph P4 ["Phase 4: Validation & Knowledge<br/>(Senior Analyst / DE)"]
        direction TB
        H --> I[Atomic Red Team:<br/>Attack Simulation]
        I -- Passed --> J[Production Rule<br/>Deployment]
        J --> L[Playbook Creation:<br/>Investigation Steps]
        L --> K[Continuous SOC<br/>Monitoring]
        K -- Feedback --> D
    end

    %% Global Connections
    P1 --> P2
    P2 --> P3
    P3 --> P4

    %% Styling
    style A fill:#e1f5fe,stroke:#01579b
    style B fill:#e1f5fe,stroke:#01579b
    style D fill:#fff3e0,stroke:#e65100
    style E fill:#fff3e0,stroke:#e65100
    style G fill:#f3e5f5,stroke:#4a148c
    style H fill:#f3e5f5,stroke:#4a148c
    style J fill:#e8f5e9,stroke:#1b5e20
    style L fill:#fff9c4,stroke:#fbc02d
