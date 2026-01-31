# Detection Development Lifecycle (DDLC)

This flowchart defines the standard operating procedure for developing new detection rules in this repository.

```mermaid
graph TD
    %% Phase 1: Input and Trigger
    subgraph "Phase 1: Input & Strategy (CTI / IR Analyst)"
        A[CTI: Threat Intel & TTP Extraction] --> C{Requirement Assessment}
        B[IR: Incident Post-Mortem & Review] --> C
    end

    %% Phase 2: Logic Design (Detection Engineer)
    subgraph "Phase 2: Detection Engineering (Detection Engineer)"
        C --> D[Use Case Design: Logic Modeling & Sigma Rules]
        D --> E[Data Requirements: Fields & Schema Mapping]
    end

    %% Phase 3: Engineering Implementation (Security Engineer)
    subgraph "Phase 3: Security Engineering (Security Engineer)"
        E --> F[Gap Analysis: Log Source & Visibility Gaps]
        F --> G[Ingestion & Pipeline: Parser & Normalization]
        G --> H[Data Quality Validation: Schema & Latency Check]
    end

    %% Phase 4: Validation and Deployment
    subgraph "Phase 4: Validation & Operations (Detection Engineer / Analyst)"
        H --> I[Atomic Red Team: Attack Simulation & Testing]
        I -- Test Failed --> G
        I -- Test Passed --> J[Production Rule Deployment]
        J --> K[Continuous SOC Monitoring & Tuning]
        K -- False Positive Feedback --> D
    end

    %% Styling for Roles
    style A fill:#e1f5fe,stroke:#01579b
    style B fill:#e1f5fe,stroke:#01579b
    style D fill:#fff3e0,stroke:#e65100
    style E fill:#fff3e0,stroke:#e65100
    style G fill:#f3e5f5,stroke:#4a148c
    style H fill:#f3e5f5,stroke:#4a148c
    style J fill:#e8f5e9,stroke:#1b5e20
