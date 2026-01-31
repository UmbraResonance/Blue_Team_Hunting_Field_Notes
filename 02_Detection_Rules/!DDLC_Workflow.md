# Detection Development Lifecycle (DDLC)

This flowchart defines the standard operating procedure for developing new detection rules in this repository.

```mermaid
%%{init: {"flowchart": {"htmlLabels": true, "curve": "linear", "padding": 20}}}%%
flowchart TD
    %% Phase 1: Input and Strategy
    subgraph P1 ["Phase 1: Input & Strategy<br/>(CTI / IR Analyst)"]
        A[CTI: Threat Intel & TTP Extraction] --> C{Requirement<br/>Assessment}
        B[IR: Incident Post-Mortem & Review] --> C
    end

    %% Phase 2: Logic Design
    subgraph P2 ["Phase 2: Detection Engineering<br/>(Detection Engineer)"]
        C --> D[Use Case Design:<br/>Logic Modeling & Sigma]
        D --> E[Data Requirements:<br/>Fields & Schema Mapping]
    end

    %% Phase 3: Engineering Implementation
    subgraph P3 ["Phase 3: Security Engineering<br/>(Security Engineer)"]
        E --> F[Gap Analysis:<br/>Visibility Gaps]
        F --> G[Ingestion & Pipeline:<br/>Parser & Normalization]
        G --> H[Data Quality Check:<br/>Schema & Latency]
    end

    %% Phase 4: Validation and Deployment
    subgraph P4 ["Phase 4: Validation & Operations<br/>(Detection Engineer / Analyst)"]
        H --> I[Atomic Red Team:<br/>Attack Simulation]
        I -- Test Failed --> G
        I -- Test Passed --> J[Production Rule Deployment]
        J --> K[Continuous SOC Monitoring]
        K -- Feedback --> D
    end

    %% Styling
    style A fill:#e1f5fe,stroke:#01579b
    style B fill:#e1f5fe,stroke:#01579b
    style D fill:#fff3e0,stroke:#e65100
    style E fill:#fff3e0,stroke:#e65100
    style G fill:#f3e5f5,stroke:#4a148c
    style H fill:#f3e5f5,stroke:#4a148c
    style J fill:#e8f5e9,stroke:#1b5e20
