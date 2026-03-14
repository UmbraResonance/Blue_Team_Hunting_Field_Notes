# 9.3 CTI Streamliner (Methodology & Lab)

### Overview
This module facilitates the "Collection" phase of the DDLC. It is designed to aggregate multi-source threat intelligence into a readable format for daily monitoring.

### Components
1. **Intelligence Hub (FreshRSS)**: 
   - Deploy via `docker-compose.yml`.
   - Pre-configured with the feed list in `./config/feeds/`.
2. **Search Logic**:
   - Integrated into `09_Automation_Vault/9.3_Tooling_and_Pipelines/CTI_Streamliner/logic/` for rapid Obsidian lookup.

### Maintenance Note
Independent Python-based automation is currently out of scope. The focus is on maintaining a high-fidelity RSS feed list and optimized search queries.