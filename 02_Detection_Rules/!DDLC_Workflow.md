# Detection Development Lifecycle (DDLC)

This flowchart defines the standard operating procedure for developing new detection rules in this repository.

```mermaid
graph TD
    %% Phase 1: Input and Trigger
    subgraph "Phase 1: Input & Trigger (IR/CTI)"
        A[CTI: Threat Intel & TTP Extraction] --> C{Requirement Assessment}
        B[IR: Incident Post-Mortem & Review] --> C
    end

    %% Phase 2: Logic Design (Detection Engineering)
    subgraph "Phase 2: The Brain (Detection Engineering)"
        C --> D[Use Case Design: Logic Modeling & Sigma Rules]
        D --> E[Data Requirements: Fields & CIM/ECS Mapping]
    end

    %% Phase 3: Engineering Implementation (Security Engineering)
    subgraph "Phase 3: The Muscle (Security Engineering)"
        E --> F[Gap Analysis: Log Source & Visibility Gaps]
        F --> G[Ingestion & Pipeline: Parser & CIM Implementation]
        G --> H[Data Quality Validation: Schema & Latency Check]
    end

    %% Phase 4: Validation and Deployment
    subgraph "Phase 4: Validation & Feedback"
        H --> I[Atomic Red Team: Attack Simulation & Testing]
        I -- Test Failed --> G
        I -- Test Passed --> J[Production Rule Deployment]
        J --> K[Continuous SOC Monitoring & Tuning]
        K -- False Positive Feedback --> D
    end
